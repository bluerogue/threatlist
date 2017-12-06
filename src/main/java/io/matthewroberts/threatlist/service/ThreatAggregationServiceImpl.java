package io.matthewroberts.threatlist.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Scanner;
import java.util.SortedSet;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import io.matthewroberts.threatlist.util.Constants;
import io.matthewroberts.threatlist.util.Utils;

/**
 * Handles aggregation calls and persistence for external threat IPs.
 * 
 * @author matthewroberts
 *
 */
@Service("threatAggregationService")
public class ThreatAggregationServiceImpl implements ThreatAggregationService {

	public static final Logger LOGGER = LoggerFactory.getLogger(ThreatAggregationServiceImpl.class);

	private static final String EMERGINGTHREATS_URL = "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt";
	private static final String EMERGINGTHREATS_COMP_URL = "http://rules.emergingthreats.net/blockrules/compromised-ips.txt";
	private static final String MALC0DE_URL = "http://malc0de.com/bl/IP_Blacklist.txt";
	private static final String MALWAREDOMAIN_URL = "http://www.malwaredomainlist.com/hostslist/ip.txt";
	private static final String CINSSCORE_URL = "http://cinsscore.com/list/ci-badguys.txt";
	private static final String BINARY_DEFENSE_URL = "https://www.binarydefense.com/banlist.txt";
	private static final String ZEUS_URL = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist";
	private static final String NOTHINK_URL = "http://www.nothink.org/blacklist/blacklist_ssh_all.txt";

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.matthewroberts.threatlist.service.ThreatAggregationService#
	 * writeNewThreatList()
	 */
	@Override
	public void writeNewThreatList() {
		try {
			writeToTextFile(Constants.THREAT_LIST_FILE_PATH, formatThreatList(buildThreatSet()));
		} catch (IOException e) {
			LOGGER.error("", e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.matthewroberts.threatlist.service.ThreatAggregationService#
	 * archiveThreatList()
	 */
	@Override
	public void archiveThreatList() {

		File file = new File(Constants.THREAT_LIST_FILE_PATH);

		if (file.exists()) {

			LocalDateTime today = LocalDateTime.now();
			DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

			Path sourceFile = Paths.get(Constants.THREAT_LIST_FILE_PATH);
			Path targetFile = Paths.get(Constants.THREAT_LIST_PATH + "threatlist-" + today.format(formatter) + ".txt");

			try {
				Files.copy(sourceFile, targetFile, StandardCopyOption.REPLACE_EXISTING);
			} catch (IOException e) {
				LOGGER.error("", e);
			}
		}
	}

	/*
	 * Writes the threat list to a file.
	 */
	private static void writeToTextFile(String fileName, String content) throws IOException {
		Files.write(Paths.get(fileName), content.getBytes(), StandardOpenOption.CREATE);
	}

	/*
	 * Constructs a String list of IPs separated by line breaks.
	 */
	private static String formatThreatList(SortedSet<String> threatSet) {
		StringBuilder sb = new StringBuilder();
		boolean firstLine = true;
		for (String threat : threatSet) {
			if (firstLine) {
				firstLine = false;
			} else {
				sb.append(System.lineSeparator());
			}

			// Basically output validation before writing
			if (Utils.isValidIp(threat)) {
				sb.append(threat);
			}
		}
		return sb.toString();
	}

	/*
	 * Makes simple REST GET calls out to submitted URL returning a String[] of
	 * items separated by line breaks.
	 */
	private static String[] getOriginalIps(String url) {
		String threats = "";
		try {
			RestTemplate restTemplate = new RestTemplate();
			threats = restTemplate.getForObject(url, String.class);
		} catch (Exception e) {
			LOGGER.error("", e);
		}
		return threats.split("\\n");
	}

	/*
	 * Constructs a sorted set of IP addresses from external lists.
	 */
	private static SortedSet<String> buildThreatSet() {

		Comparator<String> ipComparator = new Comparator<String>() {
			@Override
			public int compare(String ip1, String ip2) {
				return stripIp(ip1).compareTo(stripIp(ip2));
			}
		};

		SortedSet<String> threatSet = new TreeSet<String>(ipComparator);

		for (String ip : getOriginalIps(EMERGINGTHREATS_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(EMERGINGTHREATS_COMP_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(MALC0DE_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(MALWAREDOMAIN_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(CINSSCORE_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(BINARY_DEFENSE_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(ZEUS_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		for (String ip : getOriginalIps(NOTHINK_URL)) {
			if (Utils.isValidIp(ip.trim())) {
				threatSet.add(ip.trim());
			}
		}

		return threatSet;
	}

	/*
	 * Use within a comparator to sort IP addresses.
	 */
	private static Long stripIp(String ip) {
		Scanner scanner = new Scanner(ip);
		scanner.useDelimiter("\\.");
		Long sortableIp = (scanner.nextLong() << 24) + (scanner.nextLong() << 16) + (scanner.nextLong() << 8)
				+ (scanner.nextLong());
		scanner.close();

		return sortableIp;
	}

}
