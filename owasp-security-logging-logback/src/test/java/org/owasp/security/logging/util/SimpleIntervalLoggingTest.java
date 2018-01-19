package org.owasp.security.logging.util;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleIntervalLoggingTest {

    private static final Logger logger = LoggerFactory.getLogger(SimpleIntervalLoggingTest.class);

    @Test
    public void doBareBonesTest() {

        logger.info("barebones test started");

        final IntervalLoggerController wd = SecurityLoggingFactory.getControllerInstance();

        wd.start();

        // Wait around to see a few status messages logged.
        final long exit_time = System.currentTimeMillis() + 1000 * 30;

        while (exit_time > System.currentTimeMillis()) {
            Thread.yield();
            try {
                Thread.sleep(100);
            } catch (@SuppressWarnings("unused") final InterruptedException e) {
            }
        }

        wd.stop();

        logger.info("barebones test finished");

    }

}
