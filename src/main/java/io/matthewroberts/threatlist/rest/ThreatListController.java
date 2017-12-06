package io.matthewroberts.threatlist.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.matthewroberts.threatlist.service.ThreatService;
import io.matthewroberts.threatlist.util.Constants;
import io.matthewroberts.threatlist.util.Utils;

/**
 * API endpoints.
 * 
 * @author matthewroberts
 */
@RestController
@RequestMapping("/")
public class ThreatListController {

	public static final Logger LOGGER = LoggerFactory.getLogger(ThreatListController.class);

	@Autowired
	ThreatService threatService;

	/**
	 * @param type
	 *            The type of response desired, e.g., <code>type=json</code>
	 * @return Returns the current threat list as plain text
	 */
	@Cacheable(value = "threatlist")
	@RequestMapping(value = "/latest", method = RequestMethod.GET)
	public ResponseEntity<?> getMasterIpList(
			@RequestParam(value = "type", required = false, defaultValue = "") String type) {

		String threatList = "";

		try {
			threatList = threatService.getIpMasterList();
		} catch (IOException e) {
			LOGGER.error("", e);
			return new ResponseEntity<Object>(Constants.EMPTY_JSON, HttpStatus.BAD_REQUEST);
		}

		if (type.toLowerCase().equals("json")) {
			Map<String, Object> responseMap = new HashMap<String, Object>();
			responseMap.put("count", Utils.countLines(threatList));
			responseMap.put("ips", threatList.replaceAll("\n", ","));
			return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(responseMap);
		}

		return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.TEXT_PLAIN).body(threatList);
	}

	/**
	 * 
	 * @param date
	 *            The date of the list to retrieve in YYYY-MM-DD format
	 * @param type
	 *            The type of response desired, e.g., <code>type=json</code>
	 * @return Returns the threat list for the submitted date as plain text
	 */
	@Cacheable(value = "threathistory")
	@RequestMapping(value = "/{date}", method = RequestMethod.GET)
	public ResponseEntity<?> getIpListByDate(@PathVariable(value = "date") String date,
			@RequestParam(value = "type", required = false, defaultValue = "") String type) {

		String threatList = "";

		if (Utils.isSimpleIsoDate(date)) {
			try {
				threatList = threatService.getIpMasterListByDate(date);
			} catch (IOException e) {
				LOGGER.error("", e);
				return new ResponseEntity<Object>("List not found for " + date, HttpStatus.NOT_FOUND);
			}

		} else {
			return new ResponseEntity<String>("Invalid date - must be in format YYYY-MM-DD", HttpStatus.BAD_REQUEST);
		}

		if (type.toLowerCase().equals("json")) {
			Map<String, Object> responseMap = new HashMap<String, Object>();
			responseMap.put("count", Utils.countLines(threatList));
			responseMap.put("ips", threatList.replaceAll("\n", ","));
			return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(responseMap);
		}

		return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.TEXT_PLAIN).body(threatList);
	}

	/**
	 * 
	 * @param ip
	 *            The IP address to check against the current list
	 * @return Returns <code>true</code> as JSON if the IP is determined to be
	 *         malicious
	 */
	@Cacheable(value = "ipcheck")
	@RequestMapping(value = "/ip/{ip:.+}", method = RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE })
	public ResponseEntity<?> checkIp(@PathVariable(value = "ip") String ip) {

		Map<String, Object> responseMap = new HashMap<String, Object>();

		if (Utils.isValidIp(ip)) {
			responseMap.put("ip", ip);
			try {
				responseMap.put("malicious", threatService.isMalicious(ip));
			} catch (IOException e) {
				LOGGER.error("", e);
				responseMap.put("error", "ip not found");
				return new ResponseEntity<Object>(responseMap, HttpStatus.NOT_FOUND);
			}
		} else {
			responseMap.put("error", "malformed IP");
			return new ResponseEntity<Map<String, Object>>(responseMap, HttpStatus.BAD_REQUEST);
		}

		return new ResponseEntity<Map<String, Object>>(responseMap, HttpStatus.OK);
	}

	/**
	 * 
	 * @param domain
	 *            The domain to check against the current list
	 * @return Returns <code>true</code> as JSON if the domain is determined to be
	 *         malicious
	 */
	@Cacheable(value = "domaincheck")
	@RequestMapping(value = "/domain/{domain:.+}", method = RequestMethod.GET, produces = {
			MediaType.APPLICATION_JSON_VALUE })
	public ResponseEntity<?> checkDomain(@PathVariable(value = "domain") String domain) {

		Map<String, Object> responseMap = new HashMap<String, Object>();

		String fqdn = domain.split("\\?")[0];

		if (Utils.isValidDomain(fqdn)) {
			responseMap.put("domain", fqdn);
			responseMap.put("ip", Utils.getDomainIp(fqdn));
			try {
				responseMap.put("malicious", threatService.isDomainMalicious(fqdn));
			} catch (Exception e) {
				LOGGER.error("", e);
				responseMap.put("error", "domain not found");
				return new ResponseEntity<Object>(responseMap, HttpStatus.NOT_FOUND);
			}
		} else {
			responseMap.put("error", "malformed domain");
			return new ResponseEntity<Map<String, Object>>(responseMap, HttpStatus.BAD_REQUEST);
		}

		return new ResponseEntity<Map<String, Object>>(responseMap, HttpStatus.OK);
	}

}