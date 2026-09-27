// A console program that statically links MFC and ATL, for checking the
// ATL/MFC half of a signature set against the linker's map of the image.

#include <afxwin.h>
#include <afxcoll.h>
#include <afxtempl.h>
#include <atlbase.h>
#include <atlstr.h>

int main() {
  if (!AfxWinInit(::GetModuleHandle(nullptr), nullptr, ::GetCommandLine(), 0))
    return 1;

  CString Text(_T("probe"));
  Text.AppendFormat(_T(" %d"), 42);
  Text.MakeUpper();

  CStringArray Words;
  Words.Add(Text);
  Words.Add(_T("mfc"));

  CMap<int, int, CString, LPCTSTR> Map;
  Map.SetAt(1, Text);
  CString Found;
  Map.Lookup(1, Found);

  CArray<double, double> Values;
  Values.Add(1.5);
  Values.SetSize(8);

  CStringList List;
  List.AddTail(Found);

  CTime Now = CTime::GetCurrentTime();
  CString Stamp = Now.Format(_T("%Y-%m-%d"));

  ATL::CAtlString AtlText(Stamp);
  AtlText.Replace(_T("-"), _T("/"));

  try {
    CFile File(_T("probe_mfc.txt"), CFile::modeCreate | CFile::modeWrite);
    File.Write(static_cast<LPCTSTR>(AtlText), AtlText.GetLength() * sizeof(TCHAR));
    File.Close();
    CFile::Remove(_T("probe_mfc.txt"));
  } catch (CException *Error) {
    Error->Delete();
  }
  return static_cast<int>(Words.GetSize() + List.GetCount()) & 1;
}
