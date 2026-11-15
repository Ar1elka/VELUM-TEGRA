package com.velumtegra.xuimobile.scanner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun ResponsiveScannerColumn(
    modifier: Modifier = Modifier,
    scroll: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    BoxWithConstraints(
        modifier = modifier.fillMaxSize().safeDrawingPadding().navigationBarsPadding(),
    ) {
        val maxContentWidth = minOf(maxWidth, 1080.dp)
        val root =
            Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .widthIn(max = maxContentWidth)
                .fillMaxHeight()
                .padding(horizontal = 14.dp, vertical = 10.dp)
        val body = if (scroll) root.verticalScroll(rememberScrollState()) else root
        Column(
            modifier = body,
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content,
        )
    }
}
