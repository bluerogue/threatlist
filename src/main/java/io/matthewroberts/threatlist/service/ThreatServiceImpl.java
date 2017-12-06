package io.matthewroberts.threatlist.service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import io.matthewroberts.threatlist.util.Constants;

@Service("threatService")
public class ThreatServiceImpl implements ThreatService {

	public static final Logger LOGGER = LoggerFactory.getLogger(ThreatServiceImpl.class);

	@Override
	public String getIpMasterList() throws IOException {

		return new String(Files.readAllBytes(Paths.get(Constants.THREAT_LIST_FILE_PATH)));
	}

	@Override
	public String getIpMasterListByDate(String date) throws IOException {

		LocalDateTime today = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

		if (date.equals(today.format(formatter))) {
			return getIpMasterList();
		}

		return new String(Files.readAllBytes(Paths.get(Constants.THREAT_LIST_PATH + "threatlist-" + date + ".txt")));
	}

	@Override
	public boolean isMalicious(String ip) throws IOException {

		String threatList = new String(Files.readAllBytes(Paths.get(Constants.THREAT_LIST_FILE_PATH)));

		if (threatList.contains(ip)) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public boolean isDomainMalicious(String domain) throws Exception {

		InetAddress inetAddress = InetAddress.getByName(domain);
		String threatList = new String(Files.readAllBytes(Paths.get(Constants.THREAT_LIST_FILE_PATH)));

		if (threatList.contains(inetAddress.getHostAddress().trim())) {
			return true;
		} else {
			return false;
		}

	}

}
