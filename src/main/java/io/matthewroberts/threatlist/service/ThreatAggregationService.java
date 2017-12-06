package io.matthewroberts.threatlist.service;

public interface ThreatAggregationService {

	/**
	 * Writes the latest list of IPs to a file.
	 */
	public void writeNewThreatList();

	/**
	 * Copies the current list of IPs to a dated file for historic reference.
	 */
	public void archiveThreatList();

}
