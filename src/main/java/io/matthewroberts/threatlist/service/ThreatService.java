package io.matthewroberts.threatlist.service;

import java.io.IOException;
import java.net.UnknownHostException;

public interface ThreatService {

	public String getIpMasterList() throws IOException;

	public boolean isMalicious(String ip) throws IOException;

	public String getIpMasterListByDate(String date) throws IOException;

	public boolean isDomainMalicious(String domain) throws Exception;

}
