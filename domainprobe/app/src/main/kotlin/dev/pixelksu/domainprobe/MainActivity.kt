package dev.pixelksu.domainprobe

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.FileProvider
import java.io.File
import android.content.ServiceConnection
import android.os.Bundle
import android.system.Os
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.PredictiveBackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.ui.graphics.graphicsLayer
import kotlin.coroutines.cancellation.CancellationException
import rikka.shizuku.Shizuku
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.RemoveCircleOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.SaveAlt
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.KeyboardArrowUp
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateMap
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.unit.Constraints
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import kotlin.math.max
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.painterResource
import androidx.compose.foundation.Image

/* ------------------------------------------------------------ data model --- */

enum class Verdict { REACHABLE, DENIED, NA, INFO }
enum class Group { MOUNT, SOCKET, NODE, SELINUX, SYSCALL, LAB }

data class Row(val name: String, val verdict: Verdict, val token: String, val group: Group, val content: String? = null)

data class DomainResult(
    val key: String,
    val title: String,
    val context: String,     // cleaned "untrusted_app_34 · uid 10325"
    val hint: String,        // shown when there are no rows yet
    val rows: List<Row>,
    val pending: Boolean = false,
)

private val LINE = Regex("""^(.*?)\s{1,}(REACHABLE|denied|n/a|INFO)\s*(.*)$""")

/** Collapse a probe detail to a short, meaningful token. */
private fun token(verdict: Verdict, detail: String): String {
    val d = detail.trim()
    return when {
        d.startsWith("errno=13") -> "EACCES"
        d.startsWith("errno=1 ") || d == "errno=1" -> "EPERM"
        d.startsWith("errno=14") -> "EFAULT"
        d.contains("SIGSYS") -> "SIGSYS"
        d.contains("errno=E") -> Regex("errno=(E[A-Z]+)").find(d)?.groupValues?.get(1) ?: d   // JavaProbe: errno=EACCES / reached errno=EPERM
        d.startsWith("killed by signal") -> "signal " + d.substringAfter("signal ").takeWhile { it.isDigit() }
        d.startsWith("errno=") -> d.substringBefore(' ')
        verdict == Verdict.REACHABLE && (d == "opened" || d == "created") -> ""  // dot says it
        d.startsWith("len=") -> d.substringBefore(" (")                          // xattr result
        else -> d
    }
}

private fun group(name: String): Group = when {
    // system_server-only research rows: kept visible but OUT of the reachable ratio so
    // the cross-domain comparison stays like-for-like (native domains never emit these).
    name.startsWith("memexec") || name == "jit-exec" || name.startsWith("native exec") ||
        name.startsWith("unsafe ") || name.startsWith("ArtMethod") || name.startsWith("syscall") ||
        name.startsWith("SIGSYS") || name.startsWith("prctl(GET_") || name.startsWith("SharedMemory") ||
        name.startsWith("AF_NETLINK") || name.startsWith("AF_PACKET") || name.startsWith("sendmsg") ||
        name.startsWith("MCAST_") || name.startsWith("IP_OPTIONS") || name == "IP_ADD_MEMBERSHIP" ||
        name.startsWith("IPV6_JOIN") || name.startsWith("IPV6_RTHDR") -> Group.LAB
    name.startsWith("mount ") || name.startsWith("mountinfo") || name.startsWith("proc ") || name.startsWith("peer ") -> Group.MOUNT
    name.startsWith("/sys/fs/selinux") || name.startsWith("selinux ") || name.startsWith("av ") -> Group.SELINUX
    name.startsWith("netlink") || name.endsWith("_socket") -> Group.SOCKET
    name.startsWith("/") -> Group.NODE
    name == "ashmem name bytes" || name == "xattr binary-safe" -> Group.NODE
    else -> Group.SYSCALL
}

private fun cleanContext(detail: String): String {
    // "u:r:untrusted_app_34:s0:c70,... uid=10325 gid=.. groups=.." ->
    // "untrusted_app_34 · uid 10325"
    val dom = detail.substringAfter("u:r:", "").substringBefore(":s0").ifEmpty { "?" }
    val uid = detail.substringAfter("uid=", "").substringBefore(' ').trim()
    return if (uid.isEmpty()) dom else "$dom · uid $uid"
}

fun parseDomain(key: String, title: String, raw: String): DomainResult {
    // rows come first; INFO content blocks follow, each "\x1e name \x1f text".
    val sections = raw.split('\u001e')
    val contentMap = HashMap<String, String>()
    for (i in 1 until sections.size) {
        val u = sections[i].indexOf('\u001f')
        if (u > 0) contentMap[sections[i].substring(0, u).trim()] = sections[i].substring(u + 1)
    }
    var ctx = ""
    val rows = mutableListOf<Row>()
    for (line in sections[0].lineSequence()) {
        val m = LINE.find(line.trimEnd()) ?: continue
        val (rawName, v, detail) = m.destructured
        val name = rawName.trim()
        if (name == "selinux context") { ctx = cleanContext(detail); continue }
        val verdict = when (v) {
            "REACHABLE" -> Verdict.REACHABLE; "denied" -> Verdict.DENIED
            "INFO" -> Verdict.INFO; else -> Verdict.NA
        }
        val tok = if (verdict == Verdict.INFO) detail.trim() else token(verdict, detail)
        rows += Row(name, verdict, tok, group(name), contentMap[name])
    }
    return DomainResult(key, title, ctx, "", rows)
}

/* --------------------------------------------------------------- activity --- */

class MainActivity : ComponentActivity() {
    private val domains = mutableStateMapOf<String, DomainResult>()
    // service channels kept alive so INFO-row content can be fetched on tap,
    // in the row's own domain, rather than read eagerly during the probe run.
    private var isolatedConn: ServiceConnection? = null
    private var isolatedBinder: IBinder? = null
    private var zygoteConn: ServiceConnection? = null
    private var zygoteProbe: IShellProbe? = null
    private var shellProbe: IShellProbe? = null
    private var shizukuHooked = false
    private val CHUNK = 262144   // per-transaction content slice, safely under the ~1MB binder cap

    // system_server's result is paged over several ordered broadcasts (its peer
    // views exceed one Binder transaction); reassemble by seq, then parse once.
    private val ssChunks = HashMap<Int, String>()
    private var ssTotal = -1
    private val resultReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) {
            val data = i?.getStringExtra("data") ?: return
            val seq = i.getIntExtra("seq", 0)
            val total = i.getIntExtra("total", 1)
            if (total != ssTotal) { ssChunks.clear(); ssTotal = total }
            ssChunks[seq] = data
            if (ssChunks.size >= ssTotal) {
                val full = buildString { for (k in 0 until ssTotal) append(ssChunks[k] ?: "") }
                ssChunks.clear(); ssTotal = -1
                domains["system_server"] = parseDomain("system_server", "system_server", full)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        registerReceiver(resultReceiver, IntentFilter("$packageName.RESULT"), Context.RECEIVER_EXPORTED)
        setContent { DomainProbeApp(domains, onRefresh = ::runProbes, onCardTap = ::onCardTap,
            onExport = ::exportReport, onFetch = ::fetchContent) }
        // Shizuku delivers its binder asynchronously; a sticky listener fires now
        // if it is already up, or when it arrives -- so we actually request the
        // permission instead of giving up on a too-early pingBinder().
        if (!shizukuHooked) {
            shizukuHooked = true
            runCatching { Shizuku.addBinderReceivedListenerSticky { runOnUiThread { probeShell() } } }
            runCatching { Shizuku.addBinderDeadListener {
                runOnUiThread { domains["shell"] = DomainResult("shell", "shell", "", "tap to open Shizuku", emptyList()) } } }
        }
        runProbes()

        // Dev harness: run the native-exec / JIT-write robustness test in THIS app
        // process (execmem allowed, crashes isolated, logcat survives). Enable with
        // `setprop debug.dp.selftest 1`. Results/breadcrumbs land under tag domainprobe.
        runCatching {
            val st = Class.forName("android.os.SystemProperties")
                .getMethod("getInt", String::class.java, Int::class.javaPrimitiveType)
                .invoke(null, "debug.dp.selftest", 0) as Int
            if (st == 1) Thread { runCatching { JavaProbe.selfTest() } }.start()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { unregisterReceiver(resultReceiver) }
        isolatedConn?.let { runCatching { unbindService(it) } }
        zygoteConn?.let { runCatching { unbindService(it) } }
    }

    private fun runProbes() {
        // in-process probe: off the UI thread (it enumerates /proc for the summaries)
        domains["untrusted_app"] = DomainResult("untrusted_app", "untrusted_app", "", "probing…", emptyList(), pending = true)
        Thread {
            val out = Probe.run(filesDir.absolutePath)
            runOnUiThread { domains["untrusted_app"] = parseDomain("untrusted_app", "untrusted_app", out) }
        }.start()

        // release any channels kept from a previous run
        isolatedConn?.let { runCatching { unbindService(it) } }; isolatedConn = null; isolatedBinder = null
        zygoteConn?.let { runCatching { unbindService(it) } }; zygoteConn = null; zygoteProbe = null

        domains["isolated_app"] = DomainResult("isolated_app", "isolated_app", "", "binding service…", emptyList(), pending = true)
        isolatedConn = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName?, svc: IBinder?) {
                isolatedBinder = svc      // kept bound for lazy content fetch
                val out = IsolatedProbeService.readResult(svc)
                runOnUiThread { domains["isolated_app"] = parseDomain("isolated_app", "isolated_app", out) }
            }
            override fun onServiceDisconnected(n: ComponentName?) { isolatedBinder = null }
        }
        bindService(Intent(this, IsolatedProbeService::class.java), isolatedConn!!, BIND_AUTO_CREATE)

        domains["zygote_next"] = DomainResult("zygote_next", "zygote_next", "", "native isolated service…", emptyList(), pending = true)
        zygoteConn = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName?, svc: IBinder?) {
                val probe = IShellProbe.Stub.asInterface(svc); zygoteProbe = probe
                val out = runCatching { probe.run() }.getOrElse { "bind error: $it" }
                runOnUiThread { domains["zygote_next"] = parseDomain("zygote_next", "zygote_next", out) }
            }
            override fun onServiceDisconnected(n: ComponentName?) { zygoteProbe = null }
        }
        runCatching { bindService(Intent(this, NativeProbeService::class.java), zygoteConn!!, BIND_AUTO_CREATE) }
        Handler(Looper.getMainLooper()).postDelayed({
            domains["zygote_next"]?.let { if (it.pending)
                domains["zygote_next"] = it.copy(pending = false, hint = "did not bind") }
        }, 6000)

        probeSystemServer()
        probeRoot()
    }

    /** Fetch one INFO row's content in its own domain, on tap. cb runs on the UI thread.
     *  Content can be multi-MB (peer mount views) while a Binder transaction is capped
     *  near 1MB, so the binder domains page it: repeated [offset,+CHUNK) reads until a
     *  short slice. untrusted_app (in-process JNI) and root (CLI stdout) have no such
     *  cap and return in one call. */
    fun fetchContent(domain: String, name: String, cb: (String) -> Unit) {
        Thread {
            val out = try {
                when (domain) {
                    "untrusted_app" -> Probe.content(filesDir.absolutePath, name)
                    "root"          -> RootProbe.content(this, name)
                    "isolated_app"  -> isolatedBinder?.let { b -> pageChunks { off -> IsolatedProbeService.readContentChunk(b, name, off, CHUNK) } } ?: "(isolated service not bound)"
                    "shell"         -> shellProbe?.let { p -> pageChunks { off -> p.contentChunk(name, off, CHUNK) } } ?: "(Shizuku not connected)"
                    "zygote_next"   -> zygoteProbe?.let { p -> pageChunks { off -> p.contentChunk(name, off, CHUNK) } } ?: "(zygote service not bound)"
                    "system_server" -> "system_server is reached through a one-shot Telecom load and returns its result by broadcast, which cannot be re-entered to page content. It reports only the row summaries here; the full per-row content for this domain is in logcat (tag: domainprobe)."
                    else            -> "(no content channel for $domain)"
                }
            } catch (t: Throwable) { "content fetch failed: $t" }
            runOnUiThread { cb(out) }
        }.start()
    }

    /** Accumulate content by paging chunks until a short (EOF) slice is returned. */
    private inline fun pageChunks(read: (Int) -> String): String {
        val sb = StringBuilder()
        var off = 0
        while (true) {
            val part = read(off)
            if (part.isEmpty()) break
            sb.append(part)
            off += part.length
            if (part.length < CHUNK) break
        }
        return sb.toString()
    }

    private var lastSsFire = 0L
    private fun probeSystemServer(force: Boolean = false) {
        // The trigger places a self-managed incoming call; do not re-fire it on
        // every pull-refresh. Keep the last result unless forced (tap) or stale.
        val now = System.currentTimeMillis()
        val have = domains["system_server"]?.rows?.isNotEmpty() == true
        if (!force && have && now - lastSsFire < 20000) return
        lastSsFire = now
        domains["system_server"] = DomainResult("system_server", "system_server", "", "via CVE-2026-49881…", emptyList(), pending = true)
        Telecom.fire(this)
        Handler(Looper.getMainLooper()).postDelayed({
            if (domains["system_server"]?.pending == true) Telecom.fire(this)
        }, 4000)
        Handler(Looper.getMainLooper()).postDelayed({
            domains["system_server"]?.let { if (it.pending)
                domains["system_server"] = it.copy(pending = false, hint = "no result — tap to retry") }
        }, 9000)
    }

    /* one entry point for the cards that can be absent/retried. */
    fun onCardTap(key: String) {
        when (key) {
            "shell" -> onShellTap()
            "system_server" -> probeSystemServer(force = true)
            "root" -> probeRoot()
        }
    }

    /* root domain, when a manager grants it. */
    private fun probeRoot() {
        domains["root"] = DomainResult("root", "root", "", "requesting su…", emptyList(), pending = true)
        Thread {
            val out = RootProbe.run(this)
            runOnUiThread {
                domains["root"] = if (out != null) parseDomain("root", "root", out)
                    else DomainResult("root", "root", "", "su not granted", emptyList())
            }
        }.start()
    }

    /* shell domain, via Shizuku/Sui when present and granted. */
    private fun probeShell() {
        val available = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
        if (!available) {
            domains["shell"] = DomainResult("shell", "shell", "", "tap to open Shizuku", emptyList())
            return
        }
        domains["shell"] = DomainResult("shell", "shell", "", "Shizuku: requesting…", emptyList(), pending = true)
        if (Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED) bindShell()
        else {
            Shizuku.addRequestPermissionResultListener(object : Shizuku.OnRequestPermissionResultListener {
                override fun onRequestPermissionResult(code: Int, grant: Int) {
                    Shizuku.removeRequestPermissionResultListener(this)
                    if (grant == android.content.pm.PackageManager.PERMISSION_GRANTED) bindShell()
                    else domains["shell"] = DomainResult("shell", "shell", "", "Shizuku permission denied", emptyList())
                }
            })
            runCatching { Shizuku.requestPermission(1001) }
        }
    }

    fun exportReport() {
        val sb = StringBuilder("domainprobe — ").append(Os.uname().release).append("\n\n")
        for (key in ORDER) {
            val d = domains[key] ?: continue
            sb.append("=== ").append(d.title).append("  ").append(d.context.ifEmpty { d.hint }).append(" ===\n")
            for (r in d.rows) {
                sb.append(String.format("%-28s %-9s %s%n", r.name,
                    when (r.verdict) { Verdict.REACHABLE -> "REACHABLE"; Verdict.DENIED -> "denied"; Verdict.INFO -> "INFO"; else -> "n/a" },
                    r.token))
                if (r.verdict == Verdict.INFO && r.content != null)
                    sb.append("    ").append(r.content.replace("\n", "\n    ")).append("\n")
            }
            sb.append("\n")
        }
        try {
            val dir = File(getExternalFilesDir(null), "reports").apply { mkdirs() }
            val f = File(dir, "domainprobe-report.txt")
            f.writeText(sb.toString())
            val uri = FileProvider.getUriForFile(this, "$packageName.files", f)
            startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "domainprobe report")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }, "Export report"))
        } catch (t: Throwable) {
            android.widget.Toast.makeText(this, "export failed: $t", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    fun onShellTap() {
        if (runCatching { Shizuku.pingBinder() }.getOrDefault(false)) probeShell()
        else runCatching {
            startActivity(packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api"))
        }.onFailure {
            startActivity(Intent(Intent.ACTION_VIEW,
                android.net.Uri.parse("https://shizuku.rikka.app/")))
        }
    }

    private var shellConn: ServiceConnection? = null
    private fun bindShell() {
        val args = Shizuku.UserServiceArgs(ComponentName(this, ShellProbeService::class.java.name))
            .daemon(false).processNameSuffix("shell").version(1)
        val conn = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName?, svc: IBinder?) {
                val probe = IShellProbe.Stub.asInterface(svc); shellProbe = probe
                val out = runCatching { probe.run() }.getOrElse { "shell service failed: $it" }
                runOnUiThread { domains["shell"] = parseDomain("shell", "shell", out) }
            }
            override fun onServiceDisconnected(n: ComponentName?) {}
        }
        shellConn = conn
        runCatching { Shizuku.bindUserService(args, conn) }
            .onFailure { domains["shell"] = DomainResult("shell", "shell", "", "bind failed: $it", emptyList()) }
    }
}

/* ---------------------------------------------------------------- the UI --- */

private val ORDER = listOf("root", "shell", "untrusted_app", "isolated_app", "zygote_next", "system_server")
private val OK = Color(0xFF3DDC84)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DomainProbeApp(domains: SnapshotStateMap<String, DomainResult>, onRefresh: () -> Unit, onCardTap: (String) -> Unit,
                   onExport: () -> Unit, onFetch: (String, String, (String) -> Unit) -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(primary = OK, surface = Color(0xFF121316), background = Color(0xFF0D0E10))) {
        val cs = MaterialTheme.colorScheme
        // detail overlay: (domain, name, content) -- content null while it loads
        var info by remember { mutableStateOf<Triple<String, String, String?>?>(null) }
        val onInfo: (String, String, String?) -> Unit = { dom, n, c ->
            if (c != null) info = Triple(dom, n, c)
            else {
                info = Triple(dom, n, null)                 // show the page with a spinner
                onFetch(dom, n) { fetched ->
                    info = info?.let { if (it.first == dom && it.second == n) Triple(dom, n, fetched) else it }
                }
            }
        }
        androidx.compose.foundation.layout.Box(Modifier.fillMaxSize()) {
        Scaffold(
            containerColor = cs.background,
            topBar = {
                TopAppBar(
                    navigationIcon = {
                        Image(painterResource(R.drawable.ic_launcher_foreground), null,
                            modifier = Modifier.padding(start = 4.dp).size(40.dp))
                    },
                    title = {
                        Column {
                            Text("Vantage", fontWeight = FontWeight.Bold, fontSize = 20.sp)
                            Text("what each Android domain can reach", fontSize = 12.sp, color = cs.onSurfaceVariant)
                        }
                    },
                    actions = { IconButton(onClick = onExport) { Icon(Icons.Outlined.SaveAlt, "export report") } },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = cs.background)
                )
            }
        ) { pad ->
            var refreshing by remember { mutableStateOf(false) }
            LaunchedEffect(refreshing) { if (refreshing) { delay(1300); refreshing = false } }
            PullToRefreshBox(
                isRefreshing = refreshing,
                onRefresh = { onRefresh(); refreshing = true },
                modifier = Modifier.padding(pad).fillMaxSize()
            ) {
                val ordered = ORDER.mapNotNull { domains[it] }
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(14.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(ordered, key = { it.key }) { DomainCard(it, onCardTap, onInfo) }
                    item { HostNote() }
                }
            }
        }
        val current = info
        if (current != null) {
            DetailScreen(current.second, current.third) { info = null }
        }
        }
    }
}

@Composable
private fun DomainCard(d: DomainResult, onCardTap: (String) -> Unit = {}, onInfo: (String, String, String?) -> Unit = { _, _, _ -> }) {
    var open by remember(d.key) { mutableStateOf(false) }
    val cs = MaterialTheme.colorScheme
    Surface(
        color = cs.surface, shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth().animateContentSize()
    ) {
        Column {
            Row(
                Modifier.fillMaxWidth().clickable { if (d.rows.isEmpty() && d.key in setOf("shell", "system_server", "root")) onCardTap(d.key) else open = !open }.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(domainIcon(d.key), null, tint = cs.primary, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(d.title, fontWeight = FontWeight.SemiBold, fontSize = 17.sp)
                    Text(
                        d.context.ifEmpty { d.hint },
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = cs.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
                if (d.pending) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = cs.primary)
                else if (d.rows.isNotEmpty()) {
                    // LAB rows (system_server-only research) are excluded so the ratio
                    // denominator is the same canonical set across every domain.
                    val core = d.rows.filter { it.group != Group.LAB }
                    RatioChip(core.count { it.verdict == Verdict.REACHABLE }, core.size)
                    Spacer(Modifier.width(6.dp))
                    Icon(if (open) Icons.Outlined.KeyboardArrowUp else Icons.Outlined.KeyboardArrowDown,
                        null, tint = cs.onSurfaceVariant, modifier = Modifier.size(20.dp))
                }
            }
            if (open && d.rows.isNotEmpty()) {
                Column(Modifier.padding(bottom = 6.dp)) {
                    for (g in listOf(Group.MOUNT, Group.SOCKET, Group.NODE, Group.SELINUX, Group.SYSCALL, Group.LAB)) {
                        val rs = d.rows.filter { it.group == g }
                        if (rs.isEmpty()) continue
                        GroupLabel(g)
                        rs.forEach { row -> RowLine(row) { n, c -> onInfo(d.key, n, c) } }
                    }
                }
            }
        }
    }
}

@Composable
private fun GroupLabel(g: Group) {
    val text = when (g) { Group.MOUNT -> "NAMESPACE & VISIBILITY"; Group.SOCKET -> "SOCKETS"; Group.NODE -> "DEVICE NODES & FILES"; Group.SELINUX -> "SELINUX POLICY"; Group.SYSCALL -> "SYSCALLS"; Group.LAB -> "SYSTEM_SERVER LAB (not counted)" }
    Text(
        text, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp)
    )
}

@Composable
private fun RowLine(r: Row, onInfo: (String, String?) -> Unit = { _, _ -> }) {
    val cs = MaterialTheme.colorScheme
    val (icon, color) = when (r.verdict) {
        Verdict.REACHABLE -> Icons.Filled.CheckCircle to OK
        Verdict.DENIED    -> Icons.Filled.Cancel to cs.error
        Verdict.INFO      -> Icons.Outlined.Info to Color(0xFF6FB5FF)
        Verdict.NA        -> Icons.Filled.RemoveCircleOutline to cs.onSurfaceVariant
    }
    val clickable = r.verdict == Verdict.INFO
    val rowMod = Modifier.fillMaxWidth()
        .then(if (clickable) Modifier.clickable { onInfo(r.name, r.content) } else Modifier)
    Box(rowMod) {
        ProbeRow(
            icon = { Icon(icon, null, tint = color, modifier = Modifier.size(16.dp)) },
            name = {
                Text(r.name, fontFamily = FontFamily.Monospace, fontSize = 13.sp,
                    color = if (clickable) Color(0xFF9CCBFF) else cs.onSurface)
            },
            token = if (r.token.isEmpty()) null else {
                {
                    Text(r.token, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = color,
                        fontWeight = if (r.verdict == Verdict.DENIED) FontWeight.Medium else FontWeight.Normal)
                }
            }
        )
    }
}

/* Icon + name + token in one custom layout. The icon is vertically centered on
 * the first line; the token is right-aligned on the same line when it fits and
 * otherwise drops to a second line under the name. The whole row is the click
 * target when onClick is set. */
@Composable
private fun ProbeRow(
    icon: @Composable () -> Unit,
    name: @Composable () -> Unit,
    token: (@Composable () -> Unit)?
) {
    Layout({ icon(); name(); token?.invoke() },
           Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 7.dp)) { m, c ->
        val iconGap = 12.dp.roundToPx()
        val gap = 24.dp.roundToPx()
        val ic = m[0].measure(Constraints())
        val avail = (c.maxWidth - ic.width - iconGap).coerceAtLeast(0)
        val np = m[1].measure(Constraints(maxWidth = avail))
        val tp = if (m.size > 2) m[2].measure(Constraints(maxWidth = avail)) else null
        val nameX = ic.width + iconGap
        val oneLine = tp == null || np.width + gap + tp.width <= avail
        if (oneLine) {
            val h = maxOf(ic.height, np.height, tp?.height ?: 0)
            layout(c.maxWidth, h) {
                ic.place(0, (h - ic.height) / 2)
                np.place(nameX, (h - np.height) / 2)
                tp?.place(c.maxWidth - tp.width, (h - tp.height) / 2)
            }
        } else {
            val line1 = maxOf(ic.height, np.height)
            val h = line1 + (tp?.height ?: 0) + 3
            layout(c.maxWidth, h) {
                ic.place(0, (line1 - ic.height) / 2)
                np.place(nameX, (line1 - np.height) / 2)
                tp?.place(nameX, line1 + 3)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailScreen(name: String, content: String?, onBack: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val progress = remember { Animatable(0f) }
    // Predictive back: track the gesture and slide/scale the page as it is swiped.
    PredictiveBackHandler(enabled = true) { events ->
        try {
            events.collect { e -> progress.snapTo(e.progress) }
            onBack()
            progress.snapTo(0f)
        } catch (c: CancellationException) {
            progress.animateTo(0f)
        }
    }
    androidx.compose.foundation.layout.Box(Modifier.fillMaxSize().graphicsLayer {
        val p = progress.value
        translationX = p * size.width * 0.35f
        scaleX = 1f - p * 0.08f; scaleY = 1f - p * 0.08f
        alpha = 1f - p * 0.25f
    }) {
    Scaffold(
        containerColor = cs.background,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "back") }
                },
                title = { Text(name, fontFamily = FontFamily.Monospace, fontSize = 16.sp) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = cs.background)
            )
        }
    ) { pad ->
        if (content == null) {
            // content is read on tap, in the row's own domain -- show progress
            Column(Modifier.padding(pad).fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = cs.primary)
                Text("reading in domain…", fontSize = 12.sp, color = cs.onSurfaceVariant,
                    modifier = Modifier.padding(top = 14.dp))
            }
        } else {
            // Content can be hundreds of KB (the root domain's peer views). Laying that
            // out as ONE unwrapped Text blocks the main thread long enough to read as a
            // freeze, so the split happens off it and a LazyColumn composes only the
            // lines on screen. Each row is given the width of the longest line, so the
            // one shared scroll state moves them together and left edges stay aligned.
            var lines by remember(content) { mutableStateOf<List<String>?>(null) }
            LaunchedEffect(content) {
                lines = withContext(Dispatchers.Default) { content.ifBlank { "(empty)" }.split('\n') }
            }
            val ls = lines
            if (ls == null) {
                Column(Modifier.padding(pad).fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center) {
                    CircularProgressIndicator(color = cs.primary)
                    Text("laying out ${content.length} bytes…", fontSize = 12.sp, color = cs.onSurfaceVariant,
                        modifier = Modifier.padding(top = 14.dp))
                }
            } else {
                val style = remember {
                    TextStyle(fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp)
                }
                val measurer = rememberTextMeasurer()
                val density = LocalDensity.current
                val lineWidth = remember(ls) {
                    val longest = (ls.maxByOrNull { it.length } ?: "").take(2000)
                    with(density) { measurer.measure(longest, style = style, softWrap = false, maxLines = 1).size.width.toDp() }
                }
                val hScroll = rememberScrollState()
                Column(Modifier.padding(pad).fillMaxSize()) {
                    Text("${ls.size} lines · ${content.length} bytes", fontSize = 11.sp,
                        color = cs.onSurfaceVariant,
                        modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 6.dp))
                    HorizontalDivider(color = cs.surfaceVariant)
                    LazyColumn(Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(top = 8.dp, bottom = 24.dp)) {
                        items(ls.size) { i ->
                            Text(ls[i].ifEmpty { " " }, style = style, color = cs.onSurface,
                                softWrap = false, maxLines = 1,
                                modifier = Modifier.padding(horizontal = 16.dp)
                                    .horizontalScroll(hScroll).width(lineWidth))
                        }
                    }
                }
            }
        }
    }
    } // graphicsLayer Box
}

@Composable
private fun RatioChip(reachable: Int, total: Int) {
    val cs = MaterialTheme.colorScheme
    val strong = reachable >= total - reachable
    Surface(
        color = if (strong) OK.copy(alpha = 0.18f) else cs.surfaceVariant,
        shape = RoundedCornerShape(9.dp)
    ) {
        Text("$reachable/$total", fontFamily = FontFamily.Monospace, fontSize = 12.sp, fontWeight = FontWeight.Medium,
            color = if (strong) OK else cs.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp))
    }
}

@Composable
private fun HostNote() {
    val cs = MaterialTheme.colorScheme
    Surface(color = cs.surface.copy(alpha = 0.5f), shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
        Text(
            "shell runs via Shizuku when it is running; shell and runas_app also run from the host with ./domainprobe.sh.",
            fontSize = 12.sp, color = cs.onSurfaceVariant, modifier = Modifier.padding(14.dp)
        )
    }
}

private fun domainIcon(key: String): ImageVector = when (key) {
    "system_server" -> Icons.Outlined.Shield
    "isolated_app"  -> Icons.Outlined.Lock
    "zygote_next"   -> Icons.Outlined.Memory
    "shell"         -> Icons.Outlined.Terminal
    "root"          -> Icons.Outlined.Bolt
    else            -> Icons.Outlined.Android
}
