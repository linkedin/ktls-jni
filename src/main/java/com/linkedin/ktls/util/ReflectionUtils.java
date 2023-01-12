package com.linkedin.ktls.util;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;


public class ReflectionUtils {
  private ReflectionUtils() {}
  public static Field makeFieldAccessible(String className, String fieldName)
      throws ClassNotFoundException, NoSuchFieldException {
    final Class<?> clazz = Class.forName(className);
    final Field field = clazz.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field;
  }

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
