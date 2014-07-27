// from http://stackoverflow.com/questions/283456/byte-array-pattern-search

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WfcPatcher
{
    internal static class ByteArrayRocks
    {
        private static readonly int[] Empty = new int[0];

        public static async Task<int[]> Locate(this byte[] self, byte[] candidate)
        {
            return await TaskEx.Run(() =>
            {
                if (IsEmptyLocate(self, candidate))
                    return Empty;

                var list = new List<int>();

                for (int i = 0; i < self.Length; i++)
                {
                    if (candidate.Length > (self.Length - i))
                        continue;

                    bool match = true;
                    for (int j = 0; match && j < candidate.Length; j++)
                        if (self[i + j] != candidate[j])
                            match = false;

                    if (!match)
                        continue;

                    list.Add(i);
                }

                return list.Count == 0 ? Empty : list.ToArray();
            });
        }

        private static bool IsEmptyLocate(byte[] array, byte[] candidate)
        {
            return array == null
                   || candidate == null
                   || array.Length == 0
                   || candidate.Length == 0
                   || candidate.Length > array.Length;
        }
    }
}