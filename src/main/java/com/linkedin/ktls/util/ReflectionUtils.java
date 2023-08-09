package com.linkedin.ktls.util;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * This is a custom utility class written for Java reflection operations.
 */
public class ReflectionUtils {
  private ReflectionUtils() {}

  /**
   * Makes a field accessible in the specified class.
   *
   * @param className  The fully qualified name of the class containing the field.
   * @param fieldName  The name of the field to make accessible.
   * @return The accessible field object.
   * @throws ClassNotFoundException If the specified class cannot be found.
   * @throws NoSuchFieldException   If the specified field cannot be found in the class.
   */
  public static Field makeFieldAccessible(String className, String fieldName)
      throws ClassNotFoundException, NoSuchFieldException {
    final Class<?> clazz = Class.forName(className);
    final Field field = clazz.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field;
  }

  /**
   * Gets the value of a field in the specified object using reflection.
   *
   * @param className The fully qualified name of the class containing the field.
   * @param fieldName The name of the field to retrieve the value from.
   * @param object    The object from which to retrieve the field value.
   * @return The value of the specified field in the object.
   * @throws ClassNotFoundException If the specified class cannot be found.
   * @throws NoSuchFieldException   If the specified field cannot be found in the class.
   * @throws IllegalAccessException If the field is inaccessible and cannot be retrieved.
   */
  public static Object getValueAtField(String className, String fieldName, Object object)
      throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
    final Class<?> clazz = Class.forName(className);
    if (object == null) {
      throw new NullPointerException();
    }
    if (!clazz.isInstance(object)) {
      throw new ClassCastException();
    }
    final Field field = clazz.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(object);
  }

  /**
   * Invokes a method on the specified object using reflection and returns the result.
   *
   * @param className  The fully qualified name of the class containing the method.
   * @param methodName The name of the method to invoke.
   * @param object     The object on which to invoke the method.
   * @return The result of invoking the specified method on the object.
   * @throws ClassNotFoundException    If the specified class cannot be found.
   * @throws NoSuchMethodException     If the specified method cannot be found in the class.
   * @throws IllegalAccessException    If the method is inaccessible and cannot be invoked.
   * @throws InvocationTargetException If an exception occurs during method invocation.
   */
  public static Object getValueAtMethod(String className, String methodName, Object object)
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException {
    final Class<?> clazz = Class.forName(className);
    if (!clazz.isInstance(object)) {
      throw new ClassCastException();
    }
    final Method method = clazz.getDeclaredMethod(methodName);
    method.setAccessible(true);
    return method.invoke(object);
  }
}
