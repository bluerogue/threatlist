package io.matthewroberts.threatlist.aggregator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.matthewroberts.threatlist.service.ThreatAggregationService;

@EnableScheduling
@Component
public class Aggregator {

	public static final Logger LOGGER = LoggerFactory.getLogger(Aggregator.class);

	@Autowired
	ThreatAggregationService threatAggregationService;

	@Scheduled(cron = "0 0 1 * * *")
	public void aggregateDailyThreats() {

		try {
			threatAggregationService.archiveThreatList();
			threatAggregationService.writeNewThreatList();
			LOGGER.info("New threat list written...");
		} catch (Exception e) {
			LOGGER.error("", e);
		}
	}

}
