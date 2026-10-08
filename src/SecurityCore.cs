using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using STATSTG = System.Runtime.InteropServices.ComTypes.STATSTG;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DanxSafety
{
    [ComImport, Guid("0000000b-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IStorage
    {
        void CreateStream([MarshalAs(UnmanagedType.LPWStr)] string name, uint mode, uint r1, uint r2, out IStream stream);
        void OpenStream([MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr reserved, uint mode, uint r2, out IStream stream);
        void CreateStorage([MarshalAs(UnmanagedType.LPWStr)] string name, uint mode, uint r1, uint r2, out IStorage storage);
        void OpenStorage([MarshalAs(UnmanagedType.LPWStr)] string name, IStorage priority, uint mode, IntPtr exclude, uint reserved, out IStorage storage);
        void CopyTo(uint count, IntPtr ids, IntPtr exclude, IStorage destination);
        void MoveElementTo([MarshalAs(UnmanagedType.LPWStr)] string name, IStorage destination, [MarshalAs(UnmanagedType.LPWStr)] string newName, uint flags);
        void Commit(uint flags);
        void Revert();
        void EnumElements(uint r1, IntPtr r2, uint r3, out IEnumSTATSTG enumeration);
        void DestroyElement([MarshalAs(UnmanagedType.LPWStr)] string name);
        void RenameElement([MarshalAs(UnmanagedType.LPWStr)] string oldName, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        void SetElementTimes([MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr created, IntPtr accessed, IntPtr modified);
        void SetClass(ref Guid clsid);
        void SetStateBits(uint bits, uint mask);
        void Stat(out STATSTG stat, uint flags);
    }

    [ComImport, Guid("0000000d-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IEnumSTATSTG
    {
        [PreserveSig] int Next(uint count, out STATSTG item, out uint fetched);
        void Skip(uint count);
        void Reset();
        void Clone(out IEnumSTATSTG enumeration);
    }

    public static class SecurityCore
    {
        [DllImport("ole32.dll", CharSet = CharSet.Unicode)]
        private static extern int StgOpenStorage(string path, IStorage priority, uint mode, IntPtr exclude, uint reserved, out IStorage storage);

        public static string Version { get { return "1.0.0"; } }
        public static string LastMessage { get; private set; }
        public static string LastBackup { get; private set; }
        public static int LastChangeCount { get; private set; }
        private const int ConfigLimit = 64 * 1024 * 1024;
        private static readonly string[] CallbackIds = {
            "ID_CRP_viewportChangeP", "ID_CRP_filePostOpenP", "ID_CRP_preRenderP",
            "ID_CRP_filePostOpen", "ID_CRP_filePostMerge", "ID_CRP_postImport" };
        private static readonly string[] GlobalNames = { "CRP_AScript", "CRP_BScript", "CRP_Authorization" };
        private static readonly string[] OtherMarkers = {
            "ADSL_BScript", "AutodeskLicSerStuckCleanBeta", "AutodeskLicSerStuckBeta",
            "PhysXPluginMfx", "PhysXPluginStl", "MSCPROP" };

        private sealed class Chunk
        {
            internal ushort Id;
            internal bool Container;
            internal byte[] Raw;
            internal byte[] Payload;
        }

        private static void Release(object obj)
        {
            if (obj != null && Marshal.IsComObject(obj)) Marshal.FinalReleaseComObject(obj);
        }

        private static IStorage OpenStorage(string path, bool write)
        {
            IStorage storage;
            Marshal.ThrowExceptionForHR(StgOpenStorage(path, null, write ? 0x12u : 0x20u, IntPtr.Zero, 0, out storage));
            return storage;
        }

        private static byte[] ReadStream(IStorage storage, string name, int limit)
        {
            IStream stream = null;
            IntPtr readCount = Marshal.AllocHGlobal(4);
            try
            {
                storage.OpenStream(name, IntPtr.Zero, 0x10u, 0, out stream);
                STATSTG stat;
                stream.Stat(out stat, 1);
                if (stat.cbSize > limit || stat.cbSize < 0) throw new IOException("嵌入数据超出检查上限，未修改文件。");
                byte[] result = new byte[(int)stat.cbSize];
                stream.Read(result, result.Length, readCount);
                if (Marshal.ReadInt32(readCount) != result.Length) throw new IOException("嵌入数据读取不完整。");
                return result;
            }
            finally { Marshal.FreeHGlobal(readCount); Release(stream); }
        }

        private static Dictionary<string, string> StreamHashes(string path)
        {
            IStorage storage = null;
            IEnumSTATSTG items = null;
            Dictionary<string, string> hashes = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                storage = OpenStorage(path, false);
                storage.EnumElements(0, IntPtr.Zero, 0, out items);
                STATSTG item; uint fetched;
                while (items.Next(1, out item, out fetched) == 0 && fetched == 1)
                {
                    if (item.type != 2) throw new IOException("发现不支持的嵌套存储，未修改文件。");
                    IStream stream = null;
                    IntPtr readCount = Marshal.AllocHGlobal(4);
                    try
                    {
                        storage.OpenStream(item.pwcsName, IntPtr.Zero, 0x10u, 0, out stream);
                        using (SHA256 sha = SHA256.Create())
                        {
                            byte[] buffer = new byte[1024 * 1024];
                            long remaining = item.cbSize;
                            while (remaining > 0)
                            {
                                int count = (int)Math.Min(remaining, buffer.Length);
                                stream.Read(buffer, count, readCount);
                                int actual = Marshal.ReadInt32(readCount);
                                if (actual != count) throw new IOException("完整性校验读取失败。");
                                sha.TransformBlock(buffer, 0, count, buffer, 0);
                                remaining -= count;
                            }
                            sha.TransformFinalBlock(new byte[0], 0, 0);
                            hashes[item.pwcsName] = Hex(sha.Hash);
                        }
                    }
                    finally { Marshal.FreeHGlobal(readCount); Release(stream); }
                }
                return hashes;
            }
            finally { Release(items); Release(storage); }
        }

        private static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
        private static string FileHash(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 sha = SHA256.Create()) return Hex(sha.ComputeHash(stream));
        }

        private static byte[] Slice(byte[] data, int start, int length)
        {
            byte[] result = new byte[length]; Buffer.BlockCopy(data, start, result, 0, length); return result;
        }

        private static List<Chunk> Chunks(byte[] data)
        {
            List<Chunk> result = new List<Chunk>();
            int offset = 0;
            while (offset < data.Length)
            {
                if (data.Length - offset < 6) throw new IOException("不支持的场景脚本结构，未修改文件。");
                uint stored = BitConverter.ToUInt32(data, offset + 2);
                uint length = stored & 0x7fffffffu;
                if (length < 6 || length > data.Length - offset) throw new IOException("场景脚本结构校验失败，未修改文件。");
                Chunk chunk = new Chunk();
                chunk.Id = BitConverter.ToUInt16(data, offset);
                chunk.Container = (stored & 0x80000000u) != 0;
                chunk.Raw = Slice(data, offset, (int)length);
                chunk.Payload = Slice(data, offset + 6, (int)length - 6);
                result.Add(chunk); offset += (int)length;
            }
            return result;
        }

        private static byte[] Join(List<byte[]> records)
        {
            using (MemoryStream stream = new MemoryStream())
            { foreach (byte[] item in records) stream.Write(item, 0, item.Length); return stream.ToArray(); }
        }

        private static byte[] Encode(Chunk chunk, byte[] payload)
        {
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                writer.Write(chunk.Id);
                writer.Write((uint)(payload.Length + 6) | (chunk.Container ? 0x80000000u : 0));
                writer.Write(payload); return stream.ToArray();
            }
        }

        private static bool Contains(byte[] data, string text)
        {
            byte[] needle = Encoding.Unicode.GetBytes(text);
            for (int i = 0; i <= data.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++) if (data[i+j] != needle[j]) { found = false; break; }
                if (found) return true;
            }
            return false;
        }

        private static string CallbackName(Chunk chunk)
        {
            byte[] data = chunk.Payload;
            if (data.Length < 10) throw new IOException("回调记录不完整。");
            int length = checked((int)BitConverter.ToUInt32(data, 6));
            if (length < 0 || length > (data.Length - 14) / 2) throw new IOException("回调名称长度无效。");
            return Encoding.Unicode.GetString(data, 10, length * 2).TrimEnd('\0');
        }

        private static string GlobalName(Chunk chunk)
        {
            if (chunk.Id != 0x1a || chunk.Container || chunk.Payload.Length < 4) throw new IOException("不支持的持久变量记录。");
            int length = checked((int)BitConverter.ToUInt32(chunk.Payload, 0));
            if (length < 0 || length != (chunk.Payload.Length - 4) / 2) throw new IOException("持久变量名称长度无效。");
            return Encoding.Unicode.GetString(chunk.Payload, 4, length * 2).TrimEnd('\0');
        }

        private static byte[] CleanConfig(byte[] config, out int changes)
        {
            changes = 0;
            List<byte[]> rootKept = new List<byte[]>();
            foreach (Chunk root in Chunks(config))
            {
                if (root.Id != 0x2180) { rootKept.Add(root.Raw); continue; }
                if (!root.Container) throw new IOException("不支持的 MAXScript 存储结构。");
                List<byte[]> kept = new List<byte[]>();
                foreach (Chunk item in Chunks(root.Payload))
                {
                    if (item.Id == 0x71 && Array.IndexOf(CallbackIds, CallbackName(item)) >= 0)
                    {
                        if (!Contains(item.Payload, "CRP_BScript") && !Contains(item.Payload, "CRP_Write"))
                            throw new IOException("发现同名但内容不匹配的回调，拒绝自动删除。");
                        changes++; continue;
                    }
                    if (item.Id == 0x30)
                    {
                        if (!item.Container) throw new IOException("持久变量容器格式不匹配。");
                        List<Chunk> globals = Chunks(item.Payload);
                        if (globals.Count % 2 != 0) throw new IOException("持久变量记录无法配对。");
                        List<byte[]> globalsKept = new List<byte[]>();
                        for (int i = 0; i < globals.Count; i += 2)
                        {
                            string name = GlobalName(globals[i]);
                            if (Array.IndexOf(GlobalNames, name) >= 0) { changes++; continue; }
                            globalsKept.Add(globals[i].Raw); globalsKept.Add(globals[i+1].Raw);
                        }
                        if (globalsKept.Count > 0) kept.Add(Encode(item, Join(globalsKept)));
                        continue;
                    }
                    kept.Add(item.Raw);
                }
                rootKept.Add(Encode(root, Join(kept)));
            }
            return Join(rootKept);
        }

        // 0 = no known signature; 1 = supported CRP; 2 = other known marker; -1 = inspection failed.
        public static int Probe(string path)
        {
            LastMessage = "";
            try
            {
                if (!File.Exists(path)) { LastMessage = "文件不存在或不可读取。"; return -1; }
                string ext = Path.GetExtension(path).ToLowerInvariant();
                if (ext == ".ms")
                {
                    if (new FileInfo(path).Length > 16 * 1024 * 1024) throw new IOException("启动脚本超过检查上限，未修改文件。");
                    byte[] original = File.ReadAllBytes(path); int cut;
                    if (FindScriptTail(original, out cut)) { LastMessage = "CRP 启动脚本感染"; return 1; }
                    return 0;
                }
                if (ext != ".max" && ext != ".bak" && ext != ".mx") return 0;
                IStorage storage = null;
                byte[] config;
                try { storage = OpenStorage(path, false); config = ReadStream(storage, "Config", ConfigLimit); }
                finally { Release(storage); }
                bool crp = Contains(config, "CRP_AScript") || Contains(config, "CRP_BScript") || Contains(config, "ID_CRP_");
                if (crp)
                {
                    int changes; byte[] cleaned = CleanConfig(config, out changes);
                    if (changes == 0 || Contains(cleaned, "CRP_AScript") || Contains(cleaned, "CRP_BScript") || Contains(cleaned, "ID_CRP_"))
                        throw new IOException("发现 CRP 标记，但结构未被本版本支持；未修改文件。");
                    LastMessage = "CRP 场景感染（" + changes + " 个恶意记录）";
                    return 1;
                }
                foreach (string marker in OtherMarkers) if (Contains(config, marker))
                { LastMessage = "发现其他已知恶意标记：" + marker + "。本版本只自动清理 CRP。"; return 2; }
                return 0;
            }
            catch (Exception e) { LastMessage = e.Message; return -1; }
        }

        private static bool FindScriptTail(byte[] original, out int cut)
        {
            cut = -1;
            Encoding encoding = Encoding.Default; int bom = 0;
            if (original.Length >= 2 && original[0] == 0xff && original[1] == 0xfe) { encoding = Encoding.Unicode; bom = 2; }
            else if (original.Length >= 3 && original[0] == 0xef && original[1] == 0xbb && original[2] == 0xbf) { encoding = new UTF8Encoding(false); bom = 3; }
            string text = encoding.GetString(original, bom, original.Length - bom);
            string literal = @"""(?:\\.|[^""\\])*""";
            string ini = @"setINISetting\s*\(?\s*getMAXIniFile\s*\(\s*\)\s*\)?\s*""\s*MAXScript\s*""\s*""\s*(?:LoadStartupScripts|LoadSaveSceneScripts|LoadSavePersistentGlobals)\s*""\s*""\s*1\s*""[ \t]*(?:\r?\n|$)";
            string tail = @"(?ms)^[ \t]*CRP_AScript\s*=\s*" + literal + @"\s+CRP_BScript\s*=\s*" + literal +
                          @"\s+execute\s+CRP_BScript\s*(?:" + ini + @"\s*)*\z";
            Match match = Regex.Match(text, tail, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success) return false;
            cut = bom + encoding.GetByteCount(text.Substring(0, match.Index));
            return true;
        }

        public static string BackupFile(string path, string backupRoot)
        {
            Directory.CreateDirectory(backupRoot);
            string folder = Path.Combine(backupRoot, DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + "_" + Guid.NewGuid().ToString("N").Substring(0,8));
            Directory.CreateDirectory(folder);
            string backup = Path.Combine(folder, Path.GetFileName(path) + ".infected-backup");
            string before = FileHash(path);
            File.Copy(path, backup, false);
            if (FileHash(backup) != before) throw new IOException("备份完整性检查失败，停止清理。");
            File.WriteAllText(Path.Combine(folder, "原始路径.txt"), path + Environment.NewLine + before, Encoding.UTF8);
            LastBackup = backup;
            return backup;
        }

        public static bool CleanFile(string path, string backupRoot)
        {
            LastMessage = ""; LastBackup = ""; LastChangeCount = 0;
            string staging = null;
            try
            {
                if (Probe(path) != 1) throw new IOException("文件没有可由本版本安全清理的 CRP 记录。");
                string fingerprint = FileHash(path);
                BackupFile(path, backupRoot);
                staging = Path.Combine(Path.GetDirectoryName(path), ".3danx-" + Guid.NewGuid().ToString("N") + ".tmp");
                File.Copy(path, staging, false);
                if (Path.GetExtension(path).Equals(".ms", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] original = File.ReadAllBytes(staging); int cut;
                    if (!FindScriptTail(original, out cut)) throw new IOException("启动脚本尾部结构变化，停止清理。");
                    File.WriteAllBytes(staging, Slice(original, 0, cut));
                    LastChangeCount = 1;
                }
                else
                {
                    Dictionary<string, string> before = StreamHashes(path);
                    IStorage storage = null; IStream stream = null;
                    try
                    {
                        storage = OpenStorage(staging, true);
                        byte[] original = ReadStream(storage, "Config", ConfigLimit);
                        int changes; byte[] cleaned = CleanConfig(original, out changes);
                        if (changes == 0 || Contains(cleaned, "CRP_AScript") || Contains(cleaned, "CRP_BScript") || Contains(cleaned, "ID_CRP_"))
                            throw new IOException("清理后的脚本标记检查失败。");
                        storage.OpenStream("Config", IntPtr.Zero, 0x12u, 0, out stream);
                        byte[] padded = new byte[original.Length]; Buffer.BlockCopy(cleaned, 0, padded, 0, cleaned.Length);
                        stream.Write(padded, padded.Length, IntPtr.Zero); stream.SetSize(cleaned.Length); stream.Commit(0);
                        Release(stream); stream = null; storage.Commit(0);
                        LastChangeCount = changes;
                    }
                    finally { Release(stream); Release(storage); }
                    Dictionary<string, string> after = StreamHashes(staging);
                    if (before.Count != after.Count) throw new IOException("场景数据流数量变化，拒绝替换原文件。");
                    foreach (KeyValuePair<string,string> item in before)
                    {
                        string hash;
                        if (!after.TryGetValue(item.Key, out hash) || (item.Key != "Config" && item.Value != hash))
                            throw new IOException("模型数据完整性检查失败，拒绝替换原文件。");
                    }
                }
                if (FileHash(path) != fingerprint) throw new IOException("原文件在清理期间发生变化，未覆盖。");
                File.Replace(staging, path, null); staging = null;
                LastMessage = "CRP 已清理，模型数据已保留。";
                return true;
            }
            catch (Exception e) { LastMessage = e.Message; return false; }
            finally { if (staging != null && File.Exists(staging)) try { File.Delete(staging); } catch { } }
        }

        public static void Log(string root, string message)
        {
            try
            {
                Directory.CreateDirectory(root);
                File.AppendAllText(Path.Combine(root, "3danxSafety.log"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + message + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }
    }
}
