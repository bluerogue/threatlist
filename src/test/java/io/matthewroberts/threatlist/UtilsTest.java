package io.matthewroberts.threatlist;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.matthewroberts.threatlist.util.Utils;

/*
 * Tests for Util methods.
 */
public class UtilsTest {

	@Test
	public void testValidIpAddress() {

		assertTrue(Utils.isValidIp("192.0.2.0"));
		assertTrue(Utils.isValidIp("192.0.255.255"));		
		assertTrue(Utils.isValidIp("198.51.100.0"));
		assertTrue(Utils.isValidIp("198.51.100.255"));
		assertTrue(Utils.isValidIp("203.0.113.0"));
		assertTrue(Utils.isValidIp("203.0.113.255"));
		assertTrue(Utils.isValidIp("10.0.0.0"));
		assertTrue(Utils.isValidIp("10.255.255.255"));
		assertTrue(Utils.isValidIp("172.16.0.0"));
		assertTrue(Utils.isValidIp("172.131.255.255"));
	}
	
	@Test
	public void testInvalidIpAddress() {

		assertTrue(!Utils.isValidIp("www.test.com"));
		assertTrue(!Utils.isValidIp("xxx.xxx.xxx.xxx"));
		assertTrue(!Utils.isValidIp("223.255.244.72116.203"));
		assertTrue(!Utils.isValidIp("ip"));
		assertTrue(!Utils.isValidIp(" "));
		assertTrue(!Utils.isValidIp(""));
	}
	
	@Test
	public void testSimpleIsoDate() {

		assertTrue(Utils.isSimpleIsoDate("2017-11-11"));
	}
	
	@Test
	public void testInvalidSimpleIsoDate() {

		assertTrue(!Utils.isSimpleIsoDate("2017-11-11 00:00:00"));
		assertTrue(!Utils.isSimpleIsoDate("1510431099571"));
		assertTrue(!Utils.isSimpleIsoDate("badinput"));
		assertTrue(!Utils.isSimpleIsoDate(" "));
		assertTrue(!Utils.isSimpleIsoDate(""));
	}
	
}
