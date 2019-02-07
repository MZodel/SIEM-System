import com.espertech.esper.client.EPRuntime;

public class LogTailerFTP implements LogTailerListener {

	// Constants
	String correctLogin = "Logged on";
	String badLogin = "password incorrect!";
	String userDeterminator = " user ";
	String isNotLoggedInDeterminator = "(not logged in)";
	String ipAddress = null;
	String ipEndDelimiter = ")>";
	int startIndexCorrectLogin = 35;
	int startIndexBadLogin = 50;

	// Variable values
	// String currentLine; // will be set in update
	String userLogin = null;
	int ftpLoginCounter = 1;
	boolean isUserLogedIn;

	EPRuntime cepFTP;

	LogTailerFTP(EPRuntime cep) {
		this.cepFTP = cep;
	}

	public void update(String line) {

		// System.out.println("New line in FTP Server Log detected # " + ftpCounter);
		// currentLine = line;

		// get ip if there is one
		ipAddress = ((ipAddress = extractIP(line)) != null) ? ipAddress : null;


		// if ipAddress is null there is no client server interaction or localhost
		if (ipAddress != null) {

			isUserLogedIn = checkUserLoggedIn(line);

			// get new user from line if there is one

			if (line.contains(userDeterminator)) {
				userLogin = getNewUserFromLine(line);
			}

			// login attempt unsuccessful
			if (line.contains(badLogin)) {
				System.out.println("# " + ftpLoginCounter + "- Bad Login Event for User '" + userLogin
						+ "' from Ip address: " + ipAddress);
				cepFTP.sendEvent(new failedAttempt(ipAddress, userLogin));
				ftpLoginCounter++;
			}

			// login attempt successful
			else if (line.contains(correctLogin)) {
				System.out.println("# " + ftpLoginCounter + "- Correct Login Event for User '" + userLogin
						+ "' from Ip address: " + ipAddress);
				cepFTP.sendEvent(new successAttempt(ipAddress, userLogin));
				ftpLoginCounter++;
			}
		}
	}

	public String getNewUserFromLine(String currentLine) {

		String user = null;

		int userChangeIndex = 50;
		int notLoggedInIndex = 68;

		// User change, when already logged in
		if (isUserLogedIn == true) {

			user = currentLine.substring(userChangeIndex, currentLine.length());
			System.out.println("Changing user to: '" + user + "'");
		}

		// login attempt from not logged in user
		else if (isUserLogedIn == false) {

			user = currentLine.substring(notLoggedInIndex, currentLine.length());
			System.out.println("Login with username '" + user + "' detected");
		}

		return user;
	}

	public boolean checkUserLoggedIn(String currentLine) {

		if (currentLine.contains(isNotLoggedInDeterminator)) {
			return false;
		}
		return true;
	}


	// TODO Pattern für IPv6 implementieren
	public static String extractIP(String line) {
		java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?<!\\d|\\d\\.)"
				+ "(?:[01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + "(?:[01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
				+ "(?:[01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + "(?:[01]?\\d\\d?|2[0-4]\\d|25[0-5])" 
				+ "(?!\\d|\\.\\d)")
				.matcher(line);
		return m.find() ? m.group() : null;
	}

	// Exception handling

	public void handleRemovedFile() {
		System.out.println("File was removed! or other Exception");
	}

	public void handleException(Exception exception) {
		System.out.println("Some exception happend");
		System.out.println(exception);
	}

	public void fileNotFound() {
		System.out.println("Error: File not Found!!");
	}
}
