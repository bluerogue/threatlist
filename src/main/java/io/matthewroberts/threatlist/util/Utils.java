package io.matthewroberts.threatlist.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple utility class, mostly validation.
 * 
 * @author matthewroberts
 *
 */
public class Utils {

	public static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

	private static final String IP_REGEX_PATTERN = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
	private static final String DOMAIN_REGEX_PATTERN = "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}$)";
	private static final String SIMPLE_ISO_DATE_REGEX_PATTERN = "\\d{4}-\\d{2}-\\d{2}";

	public static boolean isValidIp(String ip) {
		return ip.matches(IP_REGEX_PATTERN);
	}

	public static boolean isValidDomain(String domain) {
		return domain.matches(DOMAIN_REGEX_PATTERN);
	}

	public static boolean isSimpleIsoDate(String date) {
		return date.matches(SIMPLE_ISO_DATE_REGEX_PATTERN);
	}

	public static int countLines(String input) {
		return (input + " ").split("\r?\n").length;
	}

	public static String getDomainIp(String domain) {
		InetAddress inetAddress = null;
		try {
			inetAddress = InetAddress.getByName(domain);
		} catch (Exception e) {
			LOGGER.error("", e);
		}
		return inetAddress.getHostAddress();
	}

}
