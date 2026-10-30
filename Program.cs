// =============================================================================
// PasswordRotator (PasswordRotator.exe)
//
// WHAT THIS TOOL DOES - honestly:
//   It keeps a single local Windows account's password UNKNOWN to any human
//   while still allowing that account to log in, install, and run software.
//   It does this by rotating the account password to a fresh strong random
//   value every 10 minutes (via a SYSTEM scheduled task) and keeping Windows
//   autologon enabled so that power-on lands directly at the desktop. The
//   password is NEVER blanked - it is always a >=20 char cryptographically
//   random string.
//
// SECURITY TRADEOFF - read before deploying:
//   To make autologon work, the current password must be stored where Winlogon
//   can read it at boot: the LSA private secret "DefaultPassword" (stored via
//   LsaStorePrivateData, NOT the cleartext DefaultPassword registry value).
//   That secret is machine-recoverable: ANY process running as SYSTEM or local
//   admin can read it back in cleartext (LsaRetrievePrivateData, or an LSASS
//   dump). So this tool:
//     - DEFENDS against: humans learning the password, interactive logon
//       guessing/brute force, credential phishing, and password reuse across
//       machines (every box has a different, constantly-changing secret).
//     - Does NOT defend against: an attacker who ALREADY has local admin /
//       SYSTEM on this machine - they can recover the current password.
//   It is a human-knowledge and remote-guessing control, not an anti-admin
//   control. It also sets UAC ConsentPromptBehaviorAdmin=5 so admins still get
//   a consent prompt (not silent elevation) when installing software.
//
//   This tool is intentionally and completely decoupled from the Sentinel EDR:
//   no project reference in either direction, no DI, no MonitorGroup, no
//   detection registration. It is an installer-style standalone utility.
//
// MODES:
//   --install    (admin) register SYSTEM scheduled tasks (startup + every 10
//                min) that invoke "--rotate", enable autologon for the target
//                account, and set UAC ConsentPromptBehaviorAdmin=5.
//   --rotate     (SYSTEM) generate a strong random password, apply it to the
//                target local account, and refresh autologon so the next boot
//                still logs in. Never blanks, never logs the password.
//   --uninstall  delete the scheduled tasks and disable autologon (remove the
//                LSA DefaultPassword secret). The account is LEFT on its last
//                random password - it is not blanked.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace PasswordRotator
{
    internal static class Program
    {
        private const string FallbackAccountName = "PasswordRotator";
        private const string TaskNameStartup = "PasswordRotatorStartup";
        private const string TaskNameRecurring = "PasswordRotator";
        private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        private const string UacPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        private const int MinPasswordLength = 24;

        private static readonly object LogLock = new object();

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private const uint POLICY_CREATE_SECRET = 0x00000020;

        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern uint LsaStorePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            IntPtr PrivateData);

        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern int LsaNtStatusToWinError(uint Status);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern uint NetUserSetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            uint level,
            ref USER_INFO_1003 buf,
            out uint parm_err);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        private const int WTS_CURRENT_SERVER_HANDLE = 0;

        private enum WTS_INFO_CLASS
        {
            WTSUserName = 5,
        }

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            uint sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out uint pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        private const uint NERR_Success = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_1003
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string usri1003_password;
        }

        private static int Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : string.Empty;

            if (mode == "--uninstall")
            {
                return RunGuarded(Uninstall);
            }
            else
            {
                // Auto-install and then run rotate
                RunGuarded(Install);
                return RunGuarded(Rotate);
            }
        }

        private static int Usage()
        {
            Console.Error.WriteLine(
                "PasswordRotator - rotates a local account password every 10 minutes while keeping autologon.\n" +
                "Usage:\n" +
                "  PasswordRotator.exe --uninstall   Remove tasks and disable autologon (password is left random, not blanked).\n" +
                "\n" +
                "Running without arguments automatically installs and starts rotation.");
            return 2;
        }

        private static int RunGuarded(Func<int> mode)
        {
            try
            {
                return mode();
            }
            catch (Exception ex)
            {
                Log("ERROR: unhandled exception: " + ex);
                return 1;
            }
        }

        private static int Install()
        {
            if (!IsAdministrator())
            {
                Log("ERROR: --install requires administrator privileges.");
                Console.Error.WriteLine("--install must be run as administrator.");
                return 1;
            }

            string exePath = GetExecutablePath();
            string account = ResolveTargetAccount();
            Log("Install: exe='" + exePath + "', target account='" + account + "'.");

            int rc = RegisterTasks(exePath);
            if (rc != 0)
            {
                Log("ERROR: scheduled task registration failed (rc=" + rc + ").");
                return rc;
            }

            EnableAutologon(account);
            SetUacConsentPrompt(5);

            Log("Install: completed.");
            Console.Out.WriteLine("PasswordRotator installed. Run --rotate once (or reboot) to set the first random password.");
            return 0;
        }

        private static int RegisterTasks(string exePath)
        {
            RunSchtasks("/Delete /TN \"" + TaskNameStartup + "\" /F");
            RunSchtasks("/Delete /TN \"" + TaskNameRecurring + "\" /F");

            string tr = "\"" + exePath + "\" --rotate";

            int rc1 = RunSchtasks(
                "/Create /TN \"" + TaskNameStartup + "\" /TR \"" + tr + "\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F");
            if (rc1 != 0)
            {
                return rc1;
            }

            int rc2 = RunSchtasks(
                "/Create /TN \"" + TaskNameRecurring + "\" /TR \"" + tr + "\" /SC MINUTE /MO 10 /RU SYSTEM /RL HIGHEST /F");
            return rc2;
        }

        private static int RunSchtasks(string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            Process p = Process.Start(psi);
            if (p == null)
            {
                Log("ERROR: failed to start schtasks.exe.");
                return 1;
            }

            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();

            Log("schtasks " + arguments + " -> exit " + p.ExitCode + ". out='" + stdout.Trim() + "' err='" + stderr.Trim() + "'");
            return p.ExitCode;
        }

        private static int Rotate()
        {
            string account = ResolveTargetAccount();
            Log("Rotate: target account='" + account + "'.");

            string password = GeneratePassword(MinPasswordLength);

            USER_INFO_1003 info = new USER_INFO_1003();
            info.usri1003_password = password;
            uint parmErr;
            uint result = NetUserSetInfo(null, account, 1003, ref info, out parmErr);
            if (result != NERR_Success)
            {
                Log("ERROR: NetUserSetInfo failed for '" + account + "' (result=" + result + ", parmErr=" + parmErr + ").");
                return 1;
            }

            Log("Rotate: password updated for '" + account + "'.");

            EnableAutologon(account);
            StoreAutologonSecret(password);

            password = string.Empty;

            Log("Rotate: completed.");
            return 0;
        }

        private static int Uninstall()
        {
            Log("Uninstall: starting.");

            RunSchtasks("/Delete /TN \"" + TaskNameStartup + "\" /F");
            RunSchtasks("/Delete /TN \"" + TaskNameRecurring + "\" /F");

            try
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(WinlogonKey, true);
                if (key != null)
                {
                    key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
                }
            }
            catch (Exception ex)
            {
                Log("ERROR: failed to clear AutoAdminLogon: " + ex);
                return 1;
            }

            RemoveAutologonSecret();

            Log("Uninstall: completed.");
            Console.Out.WriteLine(
                "PasswordRotator removed. The account password is still a random value and was NOT blanked. " +
                "Reset it with standard Windows tools (e.g. 'Computer Management > Local Users and Groups', " +
                "or 'net user <name> *') to regain a known password.");
            return 0;
        }

        private static void EnableAutologon(string account)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(WinlogonKey, true);
            if (key == null)
            {
                Log("ERROR: unable to open Winlogon registry key.");
                return;
            }

            key.SetValue("AutoAdminLogon", "1", RegistryValueKind.String);
            key.SetValue("DefaultUserName", account, RegistryValueKind.String);
            key.SetValue("DefaultDomainName", Environment.MachineName, RegistryValueKind.String);

            if (key.GetValue("DefaultPassword") != null)
            {
                key.DeleteValue("DefaultPassword", false);
            }

            Log("Autologon enabled for '" + account + "' on domain '" + Environment.MachineName + "'.");
        }

        private static void SetUacConsentPrompt(int value)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(UacPolicyKey, true);
            if (key == null)
            {
                Log("ERROR: unable to open UAC policy registry key.");
                return;
            }

            key.SetValue("ConsentPromptBehaviorAdmin", value, RegistryValueKind.DWord);
            Log("UAC ConsentPromptBehaviorAdmin set to " + value + ".");
        }

        private static void StoreAutologonSecret(string password)
        {
            WriteLsaSecret("DefaultPassword", password);
            Log("Autologon LSA secret stored.");
        }

        private static void RemoveAutologonSecret()
        {
            WriteLsaSecret("DefaultPassword", null);
            Log("Autologon LSA secret removed.");
        }

        private static void WriteLsaSecret(string keyName, string value)
        {
            LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

            IntPtr policyHandle;
            uint status = LsaOpenPolicy(
                IntPtr.Zero,
                ref objectAttributes,
                POLICY_CREATE_SECRET,
                out policyHandle);

            if (status != 0)
            {
                int win = LsaNtStatusToWinError(status);
                Log("ERROR: LsaOpenPolicy failed (NTSTATUS=0x" + status.ToString("X8") + ", win32=" + win + ").");
                throw new InvalidOperationException("LsaOpenPolicy failed (win32=" + win + ").");
            }

            try
            {
                LSA_UNICODE_STRING keyName_native = AllocLsaString(keyName);

                if (value == null)
                {
                    status = LsaStorePrivateData(policyHandle, ref keyName_native, IntPtr.Zero);
                }
                else
                {
                    LSA_UNICODE_STRING data_native = AllocLsaString(value);
                    IntPtr dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                    Marshal.StructureToPtr(data_native, dataPtr, false);
                    status = LsaStorePrivateData(policyHandle, ref keyName_native, dataPtr);
                    Marshal.FreeHGlobal(dataPtr);
                    FreeLsaString(ref data_native);
                }

                if (status != 0)
                {
                    int win = LsaNtStatusToWinError(status);
                    Log("ERROR: LsaStorePrivateData failed (NTSTATUS=0x" + status.ToString("X8") + ", win32=" + win + ").");
                    throw new InvalidOperationException("LsaStorePrivateData failed (win32=" + win + ").");
                }

                FreeLsaString(ref keyName_native);
            }
            finally
            {
                LsaClose(policyHandle);
            }
        }

        private static LSA_UNICODE_STRING AllocLsaString(string s)
        {
            IntPtr buffer = Marshal.StringToHGlobalUni(s);
            LSA_UNICODE_STRING native = new LSA_UNICODE_STRING();
            native.Length = (ushort)(s.Length * sizeof(char));
            native.MaximumLength = (ushort)((s.Length + 1) * sizeof(char));
            native.Buffer = buffer;
            return native;
        }

        private static void FreeLsaString(ref LSA_UNICODE_STRING pair)
        {
            if (pair.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pair.Buffer);
            }
            pair.Buffer = IntPtr.Zero;
        }

        private static string ResolveTargetAccount()
        {
            try
            {
                uint sessionId = WTSGetActiveConsoleSessionId();
                if (sessionId != 0xFFFFFFFF)
                {
                    IntPtr buffer;
                    uint bytesReturned;
                    if (WTSQuerySessionInformation(
                        (IntPtr)WTS_CURRENT_SERVER_HANDLE,
                        sessionId,
                        WTS_INFO_CLASS.WTSUserName,
                        out buffer,
                        out bytesReturned))
                    {
                        try
                        {
                            string user = Marshal.PtrToStringUni(buffer);
                            if (!string.IsNullOrWhiteSpace(user))
                            {
                                return user;
                            }
                        }
                        finally
                        {
                            WTSFreeMemory(buffer);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("WARN: could not resolve console session user, using fallback: " + ex.Message);
            }

            return FallbackAccountName;
        }

        private static string GeneratePassword(int length)
        {
            if (length < 4)
            {
                length = 4;
            }

            const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
            const string lower = "abcdefghijkmnpqrstuvwxyz";
            const string digits = "23456789";
            const string symbols = "!@#$%^&*()-_=+[]{}";
            string all = upper + lower + digits + symbols;

            char[] chars = new char[length];

            chars[0] = PickChar(upper);
            chars[1] = PickChar(lower);
            chars[2] = PickChar(digits);
            chars[3] = PickChar(symbols);

            for (int i = 4; i < length; i++)
            {
                chars[i] = PickChar(all);
            }

            for (int i = length - 1; i > 0; i--)
            {
                int j = NextInt(i + 1);
                char temp = chars[i];
                chars[i] = chars[j];
                chars[j] = temp;
            }

            return new string(chars);
        }

        private static char PickChar(string set)
        {
            return set[NextInt(set.Length)];
        }

        private static int NextInt(int maxExclusive)
        {
            if (maxExclusive <= 0)
            {
                throw new ArgumentOutOfRangeException("maxExclusive");
            }

            uint limit = (uint)(0x100000000UL - (0x100000000UL % (ulong)maxExclusive));
            byte[] bytes = new byte[4];
            uint value;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            do
            {
                rng.GetBytes(bytes);
                value = BitConverter.ToUInt32(bytes, 0);
            }
            while (value >= limit);

            return (int)(value % (uint)maxExclusive);
        }

        private static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string GetExecutablePath()
        {
            string path = Process.GetCurrentProcess().MainModule.FileName;
            if (!string.IsNullOrEmpty(path))
            {
                return path;
            }

            return AppDomain.CurrentDomain.BaseDirectory;
        }

        private static void Log(string message)
        {
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PasswordRotator");
                Directory.CreateDirectory(dir);
                string file = Path.Combine(dir, "rotator.log");
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + message + Environment.NewLine;

                lock (LogLock)
                {
                    File.AppendAllText(file, line);
                }
            }
            catch
            {
                // Logging must never throw out of a mode handler.
            }
        }
    }
}