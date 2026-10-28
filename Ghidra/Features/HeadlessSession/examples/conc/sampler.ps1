# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Process sampler of the capacity harness (ramp.py): one CSV row per interval for the daemon and its
# children. The caller sets $DaemonPid, $Out and $IntervalMs before this body.
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
"t,jvm_priv_mb,jvm_ws_mb,jvm_cpu_s,nchild,child_priv_mb,child_ws_mb,child_cpu_s,cpu_total_pct" | Out-File -Encoding ascii $Out
while ($true) {
  try {
    $j = Get-Process -Id $DaemonPid -ErrorAction Stop
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$DaemonPid" | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    $cp = 0; $cw = 0; $cc = 0.0
    foreach ($k in $kids) { $cp += $k.PrivateMemorySize64; $cw += $k.WorkingSet64; $cc += $k.TotalProcessorTime.TotalSeconds }
    $tot = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
    $t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    ("{0:F3},{1},{2},{3:F2},{4},{5},{6},{7:F2},{8}" -f $t, [int]($j.PrivateMemorySize64/1MB), [int]($j.WorkingSet64/1MB), $j.TotalProcessorTime.TotalSeconds, $kids.Count, [int]($cp/1MB), [int]($cw/1MB), $cc, $tot) | Out-File -Append -Encoding ascii $Out
  } catch { break }
  Start-Sleep -Milliseconds $IntervalMs
}
