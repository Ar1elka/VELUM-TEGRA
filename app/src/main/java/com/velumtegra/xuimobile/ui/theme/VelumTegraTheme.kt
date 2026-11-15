package com.velumtegra.xuimobile.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// A new Material 3 theme for Next, built using only the established VELUM//TEGRA
// red/black/neutral brand color values (not the legacy application UI code).
private val BrandLight = lightColorScheme(
    primary = Color(0xFF8F2626),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFF2D0CC),
    onPrimaryContainer = Color(0xFF410002),
    secondary = Color(0xFF6E2521),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFFFDAD6),
    onSecondaryContainer = Color(0xFF2C1512),
    tertiary = Color(0xFF8F2626),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFF2D0CC),
    onTertiaryContainer = Color(0xFF410002),
    background = Color(0xFFF8F8F8),
    onBackground = Color(0xFF191919),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF191919),
    surfaceVariant = Color(0xFFF3F3F3),
    onSurfaceVariant = Color(0xFF5A4D4D),
    outline = Color(0xFF5A4D4D),
    outlineVariant = Color(0xFFF2D0CC),
    surfaceTint = Color(0xFF8F2626),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF8F8F8),
    surfaceContainer = Color(0xFFF3F3F3),
    surfaceContainerHigh = Color(0xFFF3F3F3),
    surfaceContainerHighest = Color(0xFFF2D0CC),
    inverseSurface = Color(0xFF191919),
    inverseOnSurface = Color(0xFFF5F5F5),
    inversePrimary = Color(0xFFAA2024),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    scrim = Color(0xFF050505),
)

private val BrandDark = darkColorScheme(
    primary = Color(0xFFAA2024),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF2B1110),
    onPrimaryContainer = Color(0xFFFFDAD6),
    secondary = Color(0xFFAA2024),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFF1A0B0B),
    onSecondaryContainer = Color(0xFFFFDAD6),
    tertiary = Color(0xFFAA2024),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFF2B1110),
    onTertiaryContainer = Color(0xFFFFDAD6),
    background = Color(0xFF050505),
    onBackground = Color(0xFFF5F5F5),
    surface = Color(0xFF050505),
    onSurface = Color(0xFFF5F5F5),
    surfaceVariant = Color(0xFF101010),
    onSurfaceVariant = Color(0xFFBBBBBB),
    outline = Color(0xFF4D4D4D),
    outlineVariant = Color(0xFF351113),
    surfaceTint = Color(0xFFAA2024),
    surfaceContainerLowest = Color(0xFF000000),
    surfaceContainerLow = Color(0xFF050505),
    surfaceContainer = Color(0xFF0D0D0D),
    surfaceContainerHigh = Color(0xFF111111),
    surfaceContainerHighest = Color(0xFF181818),
    inverseSurface = Color(0xFFF5F5F5),
    inverseOnSurface = Color(0xFF191919),
    inversePrimary = Color(0xFF8F2626),
    error = Color(0xFFFF6B63),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFF3A1111),
    onErrorContainer = Color(0xFFFFDAD6),
    scrim = Color(0xFF000000),
)

private val NextShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(30.dp),
)

@Composable
fun VelumTegraTheme(darkTheme: Boolean = true, content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) BrandDark else BrandLight,
        shapes = NextShapes,
        content = content,
    )
}
