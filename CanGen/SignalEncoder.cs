using System;

namespace PcapReplayer
{
    public static class SignalEncoder
    {
        public static bool TryEncodePhysical(DbcSignal sig, double physical, out long raw, out string? error)
        {
            raw   = 0;
            error = null;

            if (sig.Length < 1 || sig.Length > 64)
            {
                error = $"Unsupported bit length {sig.Length}.";
                return false;
            }

            SignalValueGenerator.GetEffectiveRange(sig, out double min, out double max);
            if (double.IsNaN(physical) || physical < min || physical > max)
            {
                error = $"physical {physical} is outside [{min}, {max}]";
                return false;
            }

            if (sig.Factor == 0)
            {
                error = "Signal factor cannot be zero.";
                return false;
            }

            double rawFloat = (physical - sig.Offset) / sig.Factor;
            if (double.IsNaN(rawFloat) || double.IsInfinity(rawFloat) ||
                rawFloat > long.MaxValue || rawFloat < long.MinValue)
            {
                error = "Computed raw value is not representable.";
                return false;
            }

            // Use AwayFromZero so midpoint defaults and UI-entered .5 values map to
            // the nearest non-zero representable raw value instead of banker's rounding.
            raw = (long)Math.Round(rawFloat, MidpointRounding.AwayFromZero);
            if (!FitsInBitWidth(sig, raw, out error))
                return false;

            return true;
        }

        public static void PackBits(byte[] data8, DbcSignal sig, long raw)
        {
            if (data8 == null || data8.Length < 8)
                throw new ArgumentException("Destination buffer must be 8 bytes long.", nameof(data8));

            ulong rawBits = ToRawBits(sig, raw);

            if (sig.IsLittleEndian)
            {
                for (int i = 0; i < sig.Length; i++)
                {
                    if (((rawBits >> i) & 1UL) != 0)
                        SetBit(data8, sig.StartBit + i);
                }
                return;
            }

            int bitPosition = sig.StartBit;
            for (int i = 0; i < sig.Length; i++)
            {
                int sourceBit = sig.Length - 1 - i;
                if (((rawBits >> sourceBit) & 1UL) != 0)
                    SetBit(data8, bitPosition);

                bitPosition = NextMotorolaBit(bitPosition);
            }
        }

        private static bool FitsInBitWidth(DbcSignal sig, long raw, out string? error)
        {
            error = null;

            if (sig.IsSigned)
            {
                if (sig.Length == 64) return true;

                long min = -(1L << (sig.Length - 1));
                long max = (1L << (sig.Length - 1)) - 1;
                if (raw < min || raw > max)
                {
                    error = $"raw {raw} does not fit in {sig.Length} signed bits";
                    return false;
                }

                return true;
            }

            if (raw < 0)
            {
                error = $"raw {raw} does not fit in {sig.Length} unsigned bits";
                return false;
            }

            if (sig.Length == 64) return true;

            ulong maxUnsigned = (1UL << sig.Length) - 1;
            if ((ulong)raw > maxUnsigned)
            {
                error = $"raw {raw} does not fit in {sig.Length} unsigned bits";
                return false;
            }

            return true;
        }

        private static ulong ToRawBits(DbcSignal sig, long raw)
        {
            if (!sig.IsSigned)
                return unchecked((ulong)raw);

            ulong mask = sig.Length == 64
                ? ulong.MaxValue
                : (1UL << sig.Length) - 1;

            return unchecked((ulong)raw) & mask;
        }

        private static void SetBit(byte[] data, int bitIndex)
        {
            int byteIndex  = bitIndex / 8;
            if (byteIndex < 0 || byteIndex >= data.Length) return;
            int bitInByte  = bitIndex % 8;
            data[byteIndex] |= (byte)(1 << bitInByte);
        }

        // DBC Motorola/big-endian numbering walks MSB-first within a byte, then
        // continues at the next byte's MSB position.
        private static int NextMotorolaBit(int bitPosition)
            => bitPosition % 8 == 0 ? bitPosition + 15 : bitPosition - 1;
    }
}
