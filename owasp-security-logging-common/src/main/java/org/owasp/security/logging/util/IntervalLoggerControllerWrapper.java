package org.owasp.security.logging.util;

/**
 * Wraps the controller to enforce caller conformance to intervace specification.
 * 
 * @author Milton Smith
 * @see org.owasp.security.logging.util.DefaultIntervalLoggingController
 *
 */
class IntervalLoggerControllerWrapper implements IntervalLoggerController {

    private IntervalLoggerController wd;

    public IntervalLoggerControllerWrapper(IntervalLoggerController wd) {

        this.wd = wd;

    }

    @Override
    public void start(int interval) {

        wd.start(interval);

    }

    @Override
    public void start() {

        wd.start();
    }

    @Override
    public void stop() {
        wd.stop();
    }

    @Override
    public void setStatusMessageView(IntervalLoggerView v) {

        wd.setStatusMessageView(v);
    }

    @Override
    public void setStatusMessageModel(IntervalLoggerModel m) {

        wd.setStatusMessageModel(m);

    }

}
