package fr.julm.keycloak.providers.auth.cloudfront.test.util;

import java.lang.reflect.Field;

public class TestUtils {
    public static <T> T getPrivateStaticField(Class<?> clazz, String fieldName, Class<T> fieldType) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return fieldType.cast(field.get(null));
        } catch (Exception e) {
            throw new RuntimeException("Failed to get private static field: " + fieldName + ". Details: " + e.toString(), e);
        }
    }
}