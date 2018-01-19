package org.owasp.security.logging.util;

import java.lang.Thread.State;
import java.util.ArrayList;

/**
 * Default implementation of a IntervalLoggerModel. The DefaultIntervalLoggerModel provides basic system information that most applications will find helpful when diagnosing system problems like:
 * MemoryTotal, MemoryFree, MemoryMax, ThreadNew, ThreadRunnable, ThreadBlocked, ThreadWaiting, ThreadTerminated. Developers can include new properties or remove existing properties from the model. To
 * include a new property consider the following. <code>
 * // Add a new property to the list of current properties
 * DefaultIntervalLoggerModel model = new DefaultIntervalLoggerModel();
 * model.addProperty( new DefaultIntervalProperty("YourPropertyName") {
 *   public void refresh() {
 *	  	value = sYourPropertyStringValue;
 *	 }
 *	});
 * </code> Alternatively to remove only the ThreadNew property do the following. <code>
 * // Remove default property from middle of the list like ThreadNew
 * IntervalProperty[] properties = model.getProperties();
 * for ( IntervalProperty i : properties ) {
 *   if( i.getName().equals("ThreadNew") )
 *     model.removeProperty(i);
 *  }
 * </code>
 *
 * @author Milton Smith
 *
 */
public class DefaultIntervalLoggerModel implements IntervalLoggerModel {

    private static ThreadGroup rootThreadGroup = null;

    private final ArrayList<IntervalProperty> list = new ArrayList<>();

    public DefaultIntervalLoggerModel() {

        super();

        addProperty(new ByteIntervalProperty("MemoryTotal") {
            @Override
            public void refresh() {
                value = addUnits(Long.toString(Runtime.getRuntime().totalMemory()));
            }
        });

        addProperty(new ByteIntervalProperty("MemoryFree") {
            @Override
            public void refresh() {
                value = addUnits(Long.toString(Runtime.getRuntime().freeMemory()));
            }
        });

        addProperty(new ByteIntervalProperty("MemoryMax") {
            @Override
            public void refresh() {
                value = addUnits(Long.toString(Runtime.getRuntime().maxMemory()));
            }
        });

        addProperty(new DefaultIntervalProperty("ThreadNew") {
            @Override
            public void refresh() {
                value = Long.toString(getThreadState(State.NEW));
            }
        });

        addProperty(new DefaultIntervalProperty("ThreadRunnable") {
            @Override
            public void refresh() {
                value = Long.toString(getThreadState(State.RUNNABLE));
            }
        });

        addProperty(new DefaultIntervalProperty("ThreadBlocked") {
            @Override
            public void refresh() {
                value = Long.toString(getThreadState(State.BLOCKED));
            }
        });

        addProperty(new DefaultIntervalProperty("ThreadWaiting") {
            @Override
            public void refresh() {
                value = Long.toString(getThreadState(State.WAITING));
            }
        });

        addProperty(new DefaultIntervalProperty("ThreadTerminated") {
            @Override
            public String getValue() {
                return Long.toString(getThreadState(State.TERMINATED));
            }
        });

        // TODO: need to figure this out.
        // addProperty( new DefaultIntervalProperty("ThreadTotal") {
        // public String getValue() {
        // return Long.toString(t_new+t_);
        // }
        // }
        // );

    }

    /**
     * Add a new property to be included when printing the status message.
     * 
     * @param action
     *            Property to add
     */
    @Override
    public synchronized void addProperty(final IntervalProperty action) {

        list.add(action);

    }

    /**
     * Remove property from status messages.
     * 
     * @param action
     *            Property to remove
     */
    @Override
    public synchronized void removeProperty(final IntervalProperty action) {

        list.remove(action);

    }

    /**
     * Return all properties.
     * 
     * @return Array of all properties available for printing in status message.
     */
    @Override
    public synchronized IntervalProperty[] getProperties() {

        return list.toArray(new IntervalProperty[0]);

    }

    /**
     * Signal properties to update themselves.
     */
    @Override
    public synchronized void refresh() {

        final IntervalProperty[] properties = getProperties();

        for (final IntervalProperty p : properties) {

            p.refresh();
        }

    }

    /**
     * Utility method to retrieve the number of threads of a specified state.
     * 
     * @param state
     *            Target Thread.State to retrieve.
     * @return Total threads in specified state.
     */
    private int getThreadState(final Thread.State state) {

        final Thread[] threads = getAllThreads();
        int ct = 0;

        for (final Thread thread : threads) {
            if (state.equals(thread.getState())) {
                ct++;
            }
        }

        return ct;

    }

    /**
     * Utility method to return all threads in system owned by the root ThreadGroup.
     * 
     * @return Array of all threads.
     */
    private Thread[] getAllThreads() {

        final ThreadGroup root = getRootThreadGroup();
        int ct = Thread.activeCount();
        int n = 0;
        Thread[] threads;
        do {
            ct *= 2;
            threads = new Thread[ct];
            n = root.enumerate(threads, true);
        } while (n == ct);
        return java.util.Arrays.copyOf(threads, n);

    }

    /**
     * Utility method to retrieve the root ThreadGroup. Specifically, the root ThreadGroups is where ThreadGroup.getParent() == null.
     * 
     * @return Root ThreadGroup
     */
    private ThreadGroup getRootThreadGroup() {

        if (rootThreadGroup != null) {
            return rootThreadGroup;
        }

        ThreadGroup tg = Thread.currentThread().getThreadGroup();
        ThreadGroup ptg;
        while ((ptg = tg.getParent()) != null) {
            tg = ptg;
        }

        return tg;

    }

}
