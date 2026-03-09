import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPHeadlessServer;

public class HoldMcpServerScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        int waitSeconds = 900;

        String[] args = getScriptArgs();
        if (args != null) {
            for (String arg : args) {
                if (arg.startsWith("wait_seconds=")) {
                    try {
                        waitSeconds = Integer.parseInt(arg.substring("wait_seconds=".length()));
                    } catch (NumberFormatException e) {
                        Msg.warn(this, "Invalid wait_seconds argument; using default 900");
                    }
                }
            }
        }

        Msg.info(this, "HoldMcpServerScript: keeping analyzeHeadless alive for " + waitSeconds + "s");
        long end = System.currentTimeMillis() + (waitSeconds * 1000L);
        GhidrAssistMCPHeadlessServer mcpServer = GhidrAssistMCPHeadlessServer.getInstance();

        while (System.currentTimeMillis() < end) {
            if (currentProgram != null && mcpServer != null && mcpServer.isRunning()) {
                mcpServer.setProgram(currentProgram);
            }
            Thread.sleep(1000L);
        }

        Msg.info(this, "HoldMcpServerScript: done waiting, analyzeHeadless may exit now");
    }
}
