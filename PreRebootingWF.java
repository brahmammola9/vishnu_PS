import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class PreRebootingWF {

    private static String verbosePreference = "continue";
    private static String debugPreference = "continue";
    private static String warningPreference = "continue";
    private static String scriptName = "PreRebooting_WF";
    private static String vaultBaseURL = "https://vault.example.com/";
    private static String secretBasePath = "secrets/";
    private static boolean usingVaultLookup = true;
    String vm;
    private static String wrapToken;
    SuppressionAPIAuth suppressionAPI0Auth;
    private static final String BASE_URL = vaultBaseURL;
    public static boolean skipSuppression = true;


    public static String callVIPET(String domain, String account) {
        String pwdKey = account.toLowerCase() + "_pw";
        String uri;
        if (domain.toLowerCase().equals("opr") || domain.toLowerCase().equals("b2eprod") || domain.toLowerCase().equals("iopldapprod")) {
            uri = vaultBaseURL + secretBasePath + "dpi-prod/" + domain.toLowerCase() + "/" + account.toLowerCase();
        } else {
            uri = vaultBaseURL + secretBasePath + "dpl-test/" + domain.toLowerCase() + "/" + account.toLowerCase();
        }
        try {
            URL url = new URL(uri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("X-Vault-Token", wrapToken);
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                JSONObject jsonObj = new JSONObject(response.toString());
                String pwd = jsonObj.getString(pwdKey);
                if (pwd != null && !pwd.isEmpty()) {
                    return pwd;
                } else {
                    writeToLog("ERROR: VIPET password retrieval for " + domain + ":" + account + " failed. No password.");
                    return null;
                }
            } else {
                writeToLog("ERROR: VIPET password retrieval for " + domain + ":" + account + " failed. No Response.");
                return null;
            }
        } catch (Exception e) {
            writeToLog("ERROR: VIPET Client password retrieval for " + domain + ":" + account + " failed. Msg=" + e.getMessage());
            return null;
        }
    }

    public static String callDPL(String domain, String account) {
        try {
            Class<?> proxyClass = Class.forName("W0095751_Proxy");
            Object ps = proxyClass.newInstance();
            java.lang.reflect.Method method = proxyClass.getMethod("GetPassWord", String.class, String.class, String.class);
            String pwd = (String) method.invoke(ps, domain, account, null);
            if (pwd != null && !pwd.isEmpty()) {
                return pwd;
            } else {
                writeToLog("ERROR: Password retrieval for " + domain + ":" + account + " failed.");
                return null;
            }
        } catch (Exception e) {
            writeToLog("ERROR: DPL Powershell Client Not Installed or password retrieval for " + domain + ":" + account + " failed. MSG=" + e.getMessage());
            return null;
        }
    }

    private static void writeToLog(String message) {
        // Need to replace the logger
    	
    }

    

    public void setSuppressionAPIAccessToken(String backendServer) {
        String userName = "crmt_cct";
        String password;
        if (usingVaultLookup) {
            password = callVIPET("B2EProd", userName);
        } else {
            password = callDPL("B2EProd", userName);
        }

        String uri = "https://" + backendServer + "/token";
        String base64AuthInfo = Base64.getEncoder().encodeToString((userName + ":" + password).getBytes());

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Basic " + base64AuthInfo);

        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(uri).openConnection();
            connection.setRequestMethod("POST");
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                String token = response.toString();
                Map<String, String> oAuthHeader = new HashMap<>();
                oAuthHeader.put("Authorization", "Bearer " + token);

                suppressionAPI0Auth = new SuppressionAPIAuth(token, oAuthHeader);
            } else {
                throw new Exception("Suppression API Get-Token call failed, response code: " + responseCode);
            }
        } catch (Exception e) {
            String tmpString = "PS Warning, Suppression API Get-Token call failed, output=" + e.getMessage();
            skipSuppression = true;
            System.err.println("**WARN: [" + tmpString + "].");
            writeToCreatorDB(scriptName + ": Suppression API Get-Token call failed!");
        }
    }
    
    public void writeToCreatorDB(String msg) {
        System.out.println("**[CreatorLog]** [SF PreRebooting] " + msg);
        System.out.println(msg); // This line writes the message to verbose output
    }

    public String listSuppressionEntriesForHost(String hostName, String backendServer) {
        String uri = "https://" + backendServer + "/host/" + hostName;
        Map<String, String> headers = suppressionAPI0Auth.getHeader();

        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(uri).openConnection();
            connection.setRequestMethod("GET");
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                return response.toString();
            } else {
                throw new Exception("Suppression API List-Entries call failed, response code: " + responseCode);
            }
        } catch (Exception e) {
            String tmpString = "PS WARN, Suppression API List-Entries call failed, output=" + e.getMessage();
            System.err.println("**WARN: [" + tmpString + "]");
            writeToCreatorDB(scriptName + ": Suppression API List-Entries call failed!");
            return null;
        }
    }
    public static String getSuppressionApiResult(String hostName, String backendServer, String authorizationHeader) {
        String uri = "https://" + backendServer + "/host/" + hostName;
        StringBuilder response = new StringBuilder();
        try {
            URL url = new URL(uri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", authorizationHeader);

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
        } catch (IOException e) {
            String errorMessage = "WARN: Suppression API List-Entries call failed, output=" + e.getMessage();
            System.err.println("**" + errorMessage);
            // Optionally, you can write to a log file or do further error handling here.
            // Example: WriteToCreatorDB(scriptName + ": Suppression API List-Entries call failed!");
        }
        return response.toString();
    }

public void updateSuppressionEntriesForHost(String hostName, int duration, String comment, String entryID) {
        String backendServer = "your_backend_server_address_here";
        String uri = "https://" + backendServer + "/suppress";
        String contentType = "application/json";
        String parameters = "hostname=" + hostName + "&entryId=" + entryID;

        ZonedDateTime dateNow = ZonedDateTime.now();
        String startTime = dateNow.toOffsetDateTime().toInstant().toString();
        String endTime = dateNow.plusMinutes(duration).toOffsetDateTime().toInstant().toString();

        String body = String.format("{\"start\":\"%s\",\"end\":\"%s\",\"comment\":\"%s\"}",
                startTime, endTime, comment != null ? comment : "");

        try {
            URL url = new URL(uri + "?" + parameters);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("PATCH");
            connection.setRequestProperty("Content-Type", contentType);
            connection.setDoOutput(true);

            try (OutputStream outputStream = connection.getOutputStream()) {
                byte[] input = body.getBytes("utf-8");
                outputStream.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                System.out.println("Updated Suppression entry: " + body);
            } else {
                System.err.println("**WARN: [Suppression API Update-Entry call failed, HTTP error code: " + responseCode + "]");
            }
        } catch (Exception e) {
            System.err.println("**WARN: [Suppression API Update-Entry call failed, output=" + e.getMessage() + "]");
        }
    }

public void createSuppressionEntryForHost(String hostName, int duration, String comment) {
        String backendServer = "your_backend_server_address_here";
        String uri = "https://" + backendServer + "/suppress";
        String contentType = "application/json";

        ZonedDateTime dateNow = ZonedDateTime.now();
        String startTime = dateNow.toOffsetDateTime().toInstant().toString();
        String endTime = dateNow.plusMinutes(duration).toOffsetDateTime().toInstant().toString();

        String body = String.format("{\"hostnames\":[\"%s\"],\"start\":\"%s\",\"end\":\"%s\",\"comment\":\"%s\"}",
                hostName, startTime, endTime, comment != null ? comment : "");

        try {
            URL url = new URL(uri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", contentType);
            connection.setDoOutput(true);

            try (OutputStream outputStream = connection.getOutputStream()) {
                byte[] input = body.getBytes("utf-8");
                outputStream.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                System.out.println("Created suppression entry: " + body);
            } else {
                System.err.println("**WARN: [Suppression API Create-Entry call failed, HTTP error code: " + responseCode + "]");
            }
        } catch (Exception e) {
            System.err.println("**WARN: [Suppression API Create-Entry call failed, output=" + e.getMessage() + "]");
        }
    }

public void createOrUpdateSuppressionEntry(String hostName, int duration, String comment) {
	String suppressionEntries = null;
    String URLFilter = "/CRMTConfigs?$filter=(toupper(ConfigCategory) eq toupper('Suppression_API')) and (toupper(ConfigName) eq toupper('Event_Mgmt_Server'))";
    String backendServer = getValue(URLFilter, "ConfigValue");

    if (backendServer.length() <= 0) {
        System.err.println("**ERROR: ConfigValue not in Cloud DB. Suppression will not work. Filter: " + URLFilter);
    } else {
        setSuppressionAPIAccessToken(backendServer);
        if (skipSuppression) { 
            System.out.println("Skipping suppression due to not able to retrieve token.");
        } else {
            suppressionEntries = listSuppressionEntriesForHost(hostName, backendServer);

            if (suppressionEntries.contains("ERROR")) {
                String tmpString = "PS WARN,";
                tmpString += " SuppressionEntries contains an error, and is not able to proceed suppressing properly!.";
                System.err.println("**WARN: [" + tmpString + "].");
                writeToCreatorDB("Suppression API List-Entries call failed!");
            } else {
                int count = 0;

                if (suppressionEntries != null) {
                    for (String suppressionEntry : suppressionEntries.split(",")) {
                        if (suppressionEntry.toLowerCase().equals("crmt_cct")) {
                            count++;
                            String entryID = " ";

                            String entryComment = ""; //getComment(suppressionEntry);
                            LocalDateTime dateNow = LocalDateTime.now();
                            LocalDateTime startTime = dateNow.toInstant(ZoneOffset.UTC).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                            LocalDateTime endTime = dateNow.plusMinutes(duration).toInstant(ZoneOffset.UTC).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                            

                            Duration timeLeft = Duration.between(LocalDateTime.now(), endTime);

                            if (timeLeft.toMinutes() / duration < getSuppressionDurationPercent() / 100) {
                                System.out.println("Parms passed to update suppression entry - hostName: " + hostName + ", duration: " + duration + ", comment: " + comment + ", entryId: " + entryID);
                                String updateComment = entryComment + " updated by " + scriptName;
                                updateSuppressionEntriesForHost(hostName, duration, updateComment, entryID);
                                writeToCreatorDB("Suppression entries for hostName= [" + hostName + "] set to expire in " + duration + " minutes.");
                            } else {
                                System.out.println("No suppression entries found for hostName= [" + hostName + "]. Creating new suppression entry!");
                                System.out.println("Parms passed to create incident suppression entry - hostName: " + hostName + ", duration: " + duration + ", comment: " + comment);
                                createSuppressionEntryForHost(hostName, duration, comment);
                            }
                        }
                    }
                }
                System.out.println("Number of entries for {" + hostName + "}: " + count);
            }
        }
    } 
}

public String getValue(String URLFilter, String configName) throws IOException {
    String restURL = createFullUrl(URLFilter);
    URL url = new URL(restURL);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("GET");
    connection.setRequestProperty("Accept", "application/json");
    connection.setDoOutput(true);

    int responseCode = connection.getResponseCode();
    if (responseCode == HttpURLConnection.HTTP_OK) {
        Scanner scanner = new Scanner(url.openStream());
        StringBuilder response = new StringBuilder();
        while (scanner.hasNext()) {
            response.append(scanner.nextLine());
        }
        scanner.close();
        String jsonResult = response.toString();
        return jsonResult;// parseJson(jsonResult, configName);
    } else {
        throw new IOException("Failed to fetch data from URL. Response code: " + responseCode);
    }
}

private Map<String, String> properties; // Assuming properties are stored in a map

// Method to iterate over properties and process them
public void processProperties() {
    String mem = null;
    String cpuCount = null;
    String hostGroup = null;
    String owner = null;
    // Define other variables as needed
    
    for (Map.Entry<String, String> entry : properties.entrySet()) {
        String propName = entry.getKey();
        String propValue = entry.getValue();
        
        switch(propName) {
            case "VirtualMachine.Memory.Size":
                mem = propValue;
                break;
            case "VirtualMachine.CPU.Count":
                cpuCount = propValue;
                break;
            case "VirtualMachine.Admin.ClusterName":
                hostGroup = propValue;
                break;
            case "VirtualMachine.Admin.Owner":
                owner = propValue;
                break;
            // Handle other properties similarly
            default:
                // Handle unrecognized properties
                break;
        }
    }
    
    // Process variables as needed
    System.out.println("Memory: " + mem);
    System.out.println("CPU Count: " + cpuCount);
    System.out.println("Host Group: " + hostGroup);
    System.out.println("Owner: " + owner);
    // Print or use other variables
}

public String createFullUrl( String URLFilter) {
        return BASE_URL + URLFilter;
    }
}

class SuppressionAPIAuth {
    private String token;
    private Map<String, String> header;

    public SuppressionAPIAuth(String token, Map<String, String> header) {
        this.token = token;
        this.header = header;
    }

    public String getToken() {
        return token;
    }

    public Map<String, String> getHeader() {
        return header;
    }


}
