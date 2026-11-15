package com.velumtegra.xuimobile.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

@Composable
internal fun RevealablePasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    var revealed by remember(enabled) { mutableStateOf(false) }
    val visible = revealed && value.isNotEmpty()
    val description = if (visible) "Скрыть пароль" else "Показать пароль"
    val color = MaterialTheme.colorScheme.onSurfaceVariant
    OutlinedTextField(
        value = value,
        onValueChange = {
            if (it.isEmpty()) revealed = false
            onValueChange(it)
        },
        label = label,
        modifier = modifier,
        enabled = enabled,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            IconButton(
                onClick = { revealed = !revealed },
                enabled = enabled && value.isNotEmpty(),
                modifier = Modifier.semantics { contentDescription = description },
            ) {
                Canvas(Modifier.size(24.dp)) {
                    val w = size.width
                    val h = size.height
                    val outline = Path().apply {
                        moveTo(w * 0.08f, h / 2)
                        quadraticTo(w / 2, h * 0.03f, w * 0.92f, h / 2)
                        quadraticTo(w / 2, h * 0.97f, w * 0.08f, h / 2)
                        close()
                    }
                    val width = 1.7.dp.toPx()
                    drawPath(outline, color, style = Stroke(width))
                    drawCircle(color, radius = w * 0.12f, style = Stroke(width))
                    if (visible) drawLine(color, Offset(w * 0.16f, h * 0.16f), Offset(w * 0.84f, h * 0.84f), width)
                }
            }
        },
    )
}
