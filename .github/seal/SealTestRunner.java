import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Scoped-test helper for the seal-build.yml test-filter input: runs JUnit classes via
 * JUnitCore and BC SimpleTest classes via perform() (fails on !isSuccessful()), else main().
 */
public class SealTestRunner
{
    public static void main(String[] args) throws Exception
    {
        try
        {
            if (java.security.Security.getProvider("BC") == null)
            {
                Object p = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
                java.security.Security.addProvider((java.security.Provider)p);
            }
        }
        catch (Throwable t)
        {
            System.out.println("WARN: BC provider not registered: " + t);
        }
        int run = 0, failed = 0;
        for (String name : args)
        {
            run++;
            System.out.println("=== Running " + name);
            boolean ok;
            try
            {
                ok = runOne(Class.forName(name));
            }
            catch (Throwable t)
            {
                Throwable c = (t instanceof InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
                c.printStackTrace(System.out);
                ok = false;
            }
            System.out.println("=== " + name + (ok ? ": PASSED" : ": FAILED"));
            if (!ok)
            {
                failed++;
            }
        }
        System.out.println("Test classes run: " + run + ", Passed: " + (run - failed) + ", Failed: " + failed);
        System.exit(run > 0 && failed == 0 ? 0 : 1);
    }

    static boolean isJUnit(Class<?> c)
    {
        if (junit.framework.Test.class.isAssignableFrom(c))
        {
            return true;
        }
        try
        {
            Method m = c.getMethod("suite");
            if (Modifier.isStatic(m.getModifiers()))
            {
                return true;
            }
        }
        catch (NoSuchMethodException e)
        {
        }
        if (c.isAnnotationPresent(org.junit.runner.RunWith.class))
        {
            return true;
        }
        for (Method m : c.getMethods())
        {
            if (m.isAnnotationPresent(org.junit.Test.class))
            {
                return true;
            }
        }
        return false;
    }

    static boolean runOne(Class<?> c) throws Exception
    {
        if (isJUnit(c))
        {
            org.junit.runner.Result r = org.junit.runner.JUnitCore.runClasses(c);
            for (org.junit.runner.notification.Failure f : r.getFailures())
            {
                System.out.println("FAILED: " + f.getTestHeader() + ": " + f.getMessage());
                System.out.println(f.getTrace());
            }
            System.out.println(c.getName() + ": Tests run: " + r.getRunCount() + ", Failures: "
                + r.getFailureCount() + ", Ignored: " + r.getIgnoreCount());
            return r.wasSuccessful() && r.getRunCount() > 0;
        }
        Method perform = null;
        Constructor<?> ctor = null;
        try
        {
            perform = c.getMethod("perform");
        }
        catch (NoSuchMethodException e)
        {
        }
        try
        {
            ctor = c.getDeclaredConstructor();
        }
        catch (NoSuchMethodException e)
        {
        }
        if (perform != null && ctor != null && !Modifier.isAbstract(c.getModifiers()))
        {
            ctor.setAccessible(true);
            perform.setAccessible(true);
            Object res = perform.invoke(ctor.newInstance());
            System.out.println(res);
            Class<?> tr = Class.forName("org.bouncycastle.util.test.TestResult");
            Throwable ex = (Throwable)tr.getMethod("getException").invoke(res);
            if (ex != null)
            {
                ex.printStackTrace(System.out);
            }
            return ((Boolean)tr.getMethod("isSuccessful").invoke(res)).booleanValue();
        }
        Method main = c.getMethod("main", String[].class);
        main.setAccessible(true);
        main.invoke(null, (Object)new String[0]);
        return true;
    }
}
