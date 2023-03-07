using System;

namespace PoCLibrary
{
    public static class PoCHelpers
    {
        public static bool CheckValidOperatingSystem()
        {
            OperatingSystem os = Environment.OSVersion;
            try
            {
                if (!os.Platform.Equals(PlatformID.Win32NT))
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
