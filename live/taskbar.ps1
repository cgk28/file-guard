# Taskbar helpers: give the TrustMe live window its own identity (AppUserModelID) and icon,
# so the pinned shortcut and the running window are ONE taskbar button with the shiba icon.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TB {
  [StructLayout(LayoutKind.Sequential, Pack = 4)] struct PROPERTYKEY { public Guid fmtid; public uint pid; }
  [StructLayout(LayoutKind.Explicit, Size = 24)] struct PROPVARIANT { [FieldOffset(0)] public ushort vt; [FieldOffset(8)] public IntPtr p; }
  [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IPropertyStore {
    [PreserveSig] int GetCount(out uint c);
    [PreserveSig] int GetAt(uint i, out PROPERTYKEY k);
    [PreserveSig] int GetValue(ref PROPERTYKEY k, out PROPVARIANT v);
    [PreserveSig] int SetValue(ref PROPERTYKEY k, ref PROPVARIANT v);
    [PreserveSig] int Commit();
  }
  [ComImport, Guid("0000010b-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IPersistFile {
    void GetClassID(out Guid g);
    [PreserveSig] int IsDirty();
    void Load([MarshalAs(UnmanagedType.LPWStr)] string f, uint mode);
    void Save([MarshalAs(UnmanagedType.LPWStr)] string f, bool remember);
    void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string f);
    void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string f);
  }
  [ComImport, Guid("00021401-0000-0000-C000-000000000046")] class CShellLink { }
  [DllImport("shell32.dll")] static extern int SHGetPropertyStoreForWindow(IntPtr h, ref Guid riid, out IPropertyStore ps);
  [DllImport("ole32.dll")] static extern int PropVariantClear(ref PROPVARIANT v);
  static readonly Guid FMT = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
  static void SetStr(IPropertyStore ps, uint pid, string s) {
    PROPERTYKEY k = new PROPERTYKEY { fmtid = FMT, pid = pid };
    PROPVARIANT v = new PROPVARIANT { vt = 31, p = Marshal.StringToCoTaskMemUni(s) };
    ps.SetValue(ref k, ref v); PropVariantClear(ref v);
  }
  static string GetStr(IPropertyStore ps, uint pid) {
    PROPERTYKEY k = new PROPERTYKEY { fmtid = FMT, pid = pid }; PROPVARIANT v;
    int hr = ps.GetValue(ref k, out v); if (hr != 0 || v.vt != 31) return "hr=" + hr + " vt=" + v.vt; string s = v.vt == 31 && v.p != IntPtr.Zero ? Marshal.PtrToStringUni(v.p) : null; PropVariantClear(ref v); return s;
  }
  // window: id (5), relaunch command (2), relaunch icon "path,0" (3), relaunch display name (4)
  public static void Window(IntPtr h, string id, string cmd, string icon, string name) {
    Guid g = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"); IPropertyStore ps;
    SHGetPropertyStoreForWindow(h, ref g, out ps);
    SetStr(ps, 5, id); SetStr(ps, 2, cmd); SetStr(ps, 3, icon); SetStr(ps, 4, name); ps.Commit();
  }
  public static string WindowId(IntPtr h) {
    Guid g = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"); IPropertyStore ps;
    SHGetPropertyStoreForWindow(h, ref g, out ps); return GetStr(ps, 5);
  }
  public static void Shortcut(string lnk, string id) {
    object o = new CShellLink(); ((IPersistFile)o).Load(lnk, 2);
    IPropertyStore ps = (IPropertyStore)o; SetStr(ps, 5, id); ps.Commit(); ((IPersistFile)o).Save(lnk, true);
  }
  public static string ShortcutId(string lnk) {
    object o = new CShellLink(); ((IPersistFile)o).Load(lnk, 0); return GetStr((IPropertyStore)o, 5);
  }
}
'@


