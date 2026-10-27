package app.voidwire.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import app.voidwire.android.ui.theme.VoidwireTheme

/** Small shared pieces of the M1.1 design (brand/voidwire/ui/SPEC.md §4). */

enum class ChipTone { Ok, Error, Info, Idle }

/** A pill with a 6 dp LED dot (SPEC 1.4). */
@Composable
fun VwChip(text: String, tone: ChipTone, modifier: Modifier = Modifier) {
    val c = when (tone) {
        ChipTone.Ok -> VoidwireTheme.extended.success
        ChipTone.Error -> MaterialTheme.colorScheme.error
        ChipTone.Info -> MaterialTheme.colorScheme.secondary
        ChipTone.Idle -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(
        modifier.clip(VoidwireComponentShapes.chip).background(c.copy(alpha = 0.13f)).padding(horizontal = 9.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(Modifier.size(6.dp).shadow(4.dp, CircleShape, ambientColor = c, spotColor = c).clip(CircleShape).background(c))
        Text(text.uppercase(), style = MaterialTheme.typography.labelSmall, color = c)
    }
}

/** `// SECTION` eyebrow: mono, uppercase, secondary, with an optional count. */
@Composable
fun Eyebrow(text: String, count: Int? = null, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("//", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.outline)
        Text(text.uppercase(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
        if (count != null) {
            Text("· $count", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Card (round 2): surfaceContainer, signature lg chamfer, 1 dp outlineVariant hairline, no shadow. */
@Composable
fun VwCard(
    modifier: Modifier = Modifier,
    container: Color = MaterialTheme.colorScheme.surfaceContainer,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier.fillMaxWidth(),
        shape = VoidwireComponentShapes.card,
        colors = CardDefaults.cardColors(containerColor = container),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        content = content,
    )
}

/** A 40 dp icon well (round 2: sharp, radius 2). */
@Composable
fun IconWell(icon: ImageVector, tint: Color, bg: Color, size: Int = 40) {
    Box(
        Modifier.size(size.dp).clip(VoidwireComponentShapes.iconWell).background(bg),
        contentAlignment = Alignment.Center,
    ) { Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp)) }
}

/** Top bar: optional Back, a title or the lockup, optional trailing actions. */
@Composable
fun VwTopBar(
    title: String?,
    onBack: (() -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
    actions: @Composable () -> Unit = {},
) {
    Row(
        Modifier.fillMaxWidth().height(64.dp).padding(start = if (onBack != null) 4.dp else 20.dp, end = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (onBack != null) {
            IconButton(onClick = onBack) {
                Icon(VwIcons.Back, contentDescription = "Back", tint = MaterialTheme.colorScheme.onSurface)
            }
        }
        Box(Modifier.weight(1f)) {
            if (leading != null) leading()
            else if (title != null) Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(start = 4.dp))
        }
        actions()
    }
}

/** Dashed-looking placeholder (outline at low alpha): "NO SEND HISTORY ON THIS PHONE". */
@Composable
fun Placeholder(text: String) {
    Surface(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        color = Color.Transparent,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(14.dp),
        )
    }
}

@Composable
fun KeyValue(key: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(key, style = VoidwireTheme.code.codeSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.35f))
        Text(value, style = VoidwireTheme.code.codeSmall, color = MaterialTheme.colorScheme.tertiary, modifier = Modifier.weight(0.65f))
    }
}

/** Info card used under the pair code and on Main (secondary tint). */
@Composable
fun HintCard(icon: ImageVector, content: @Composable () -> Unit) {
    Surface(
        Modifier.fillMaxWidth(),
        shape = VoidwireComponentShapes.card,
        color = MaterialTheme.colorScheme.secondary.copy(alpha = 0.08f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary.copy(alpha = 0.25f)),
    ) {
        Row(Modifier.padding(14.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(20.dp))
            Column(Modifier.weight(1f)) { content() }
        }
    }
}

/**
 * REVIEW-m11 #6 / SPEC 3.7: dashed 1 dp `outline` box, radius 6 dp, a 16 dp
 * icon plus codeSmall text ("NOTHING ABOUT YOUR SENDS IS STORED").
 */
@Composable
fun DashedNote(icon: ImageVector, text: String, modifier: Modifier = Modifier) {
    val color = MaterialTheme.colorScheme.outline
    Row(
        modifier.fillMaxWidth().drawBehind {
            val d = density
            drawRoundRect(
                color,
                cornerRadius = CornerRadius(6.dp.toPx()),
                style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f * d, 4f * d))),
            )
        }.padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
        Text(text, style = VoidwireTheme.code.codeSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
