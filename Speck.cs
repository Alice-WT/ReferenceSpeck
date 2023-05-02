namespace Alice.Security.Cryptography
{
    public class Speck
    {
        public static UInt64[] ToUInt64Array(byte[] toConvert)
        {
            //Maybe add error checks?
            var converted = new UInt64[toConvert.Length / 8];
            PackBytes(toConvert, converted);
            return converted;
        }
        public static void PackBytes(byte[] toPack, UInt64[] packInto)
        {//I can probably use some kind of memory copy thing here, I don't think order matters as long as it's the same
            for (int i = 0; i < packInto.Length; ++i)
            {
                packInto[i] = toPack[i * 8];
                packInto[i] |= ((UInt64)toPack[i * 8 + 1] << 8);
                packInto[i] |= ((UInt64)toPack[i * 8 + 2] << 16);
                packInto[i] |= ((UInt64)toPack[i * 8 + 3] << 24);
                packInto[i] |= ((UInt64)toPack[i * 8 + 4] << 32);
                packInto[i] |= ((UInt64)toPack[i * 8 + 5] << 40);
                packInto[i] |= ((UInt64)toPack[i * 8 + 6] << 48);
                packInto[i] |= ((UInt64)toPack[i * 8 + 7] << 56);
            }
        }

        public static byte[] ToBytes(UInt64[] toConvert)
        {
            var converted = new byte[toConvert.Length * 8];
            UnpackBytes(toConvert, converted);
            return converted;
        }
        public static void UnpackBytes(UInt64[] toUnpack, byte[] unpackInto)
        {//I can probably use some kind of memory copy thing here, I don't think order matters as long as it's the same
            for (int i = 0; i < toUnpack.Length; ++i)
            {
                unpackInto[i * 8] = (byte)toUnpack[i];
                unpackInto[i * 8 + 1] = (byte)(toUnpack[i] >> 8);
                unpackInto[i * 8 + 2] = (byte)(toUnpack[i] >> 16);
                unpackInto[i * 8 + 3] = (byte)(toUnpack[i] >> 24);
                unpackInto[i * 8 + 4] = (byte)(toUnpack[i] >> 32);
                unpackInto[i * 8 + 5] = (byte)(toUnpack[i] >> 40);
                unpackInto[i * 8 + 6] = (byte)(toUnpack[i] >> 48);
                unpackInto[i * 8 + 7] = (byte)(toUnpack[i] >> 56);
            }
        }

        public static void Speck128256KeySchedule(UInt64[] K, UInt64[] rk)
        {
            UInt64 i, D = K[3], C = K[2], B = K[1], A = K[0];
            for (i = 0; i < 33;)
            {
                rk[i] = A; Er64(ref B, ref A, i++);
                rk[i] = A; Er64(ref C, ref A, i++);
                rk[i] = A; Er64(ref D, ref A, i++);
            }
            rk[i] = A;
        }
        public static void Speck128256Encrypt(UInt64[] Pt, UInt64[] Ct, UInt64[] rk)
        {
            UInt64 i;
            Ct[0] = Pt[0]; Ct[1] = Pt[1];
            for (i = 0; i < 34;) Er64(ref Ct[1], ref Ct[0], rk[i++]);
        }
        public static void Speck128256Decrypt(UInt64[] Pt, UInt64[] Ct, UInt64[] rk)
        {
            int i;
            Pt[0] = Ct[0]; Pt[1] = Ct[1];
            for (i = 33; i >= 0;) Dr64(ref Pt[1], ref Pt[0], rk[i--]);
        }

        private static void Dr64(ref UInt64 x, ref UInt64 y, UInt64 k)
        {
            y ^= x;
            y = RotR64(y, 3);
            x ^= k;
            x -= y;
            x = RotL64(x, 8);
        }
        private static void Er64(ref UInt64 x, ref UInt64 y, UInt64 k)
        {
            x = RotR64(x, 8);
            x += y;
            x ^= k;
            y = RotL64(y, 3);
            y ^= x;
        }
        private static UInt64 RotL64(UInt64 x, int r)
        {
            return ((x << r) | (x >> (64 - r)));
        }
        private static UInt64 RotR64(UInt64 x, int r)
        {
            return ((x >> r) | (x << (64 - r)));
        }
    }
}
