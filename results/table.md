# Results: mean ± standard deviation

Each cell: mean ± sample standard deviation (n-1) over 3 runs.
Throughput: iperf3 TCP, 10 s, client1 to serverA, receiver side. Delay and loss: 100 pings, 0.2 s apart, per run.
Loss is worked out from 100 pings, so one run can only show steps of 1 percentage points.
Retries and other unusual events are listed in notes.txt.

## Throughput (Mbit/s)

| Protocol | none | good | normal | bad |
|---|---|---|---|---|
| Plain | 36415.01 ± 2432.97 | 63.67 ± 16.13 | 1.62 ± 0.26 | 0.51 ± 0.20 |
| Mini VPN | 289.97 ± 24.89 | 20.76 ± 3.53 | 2.00 ± 0.66 | 0.20 ± 0.10 |
| WireGuard | 2418.33 ± 104.20 | 27.30 ± 4.28 | 1.87 ± 0.78 | 0.16 ± 0.05 |
| OpenVPN | 726.53 ± 19.82 | 20.85 ± 6.47 | 1.59 ± 0.33 | 0.24 ± 0.16 |
| GRE | 27862.54 ± 2082.73 | 86.18 ± 5.75 | 2.18 ± 0.45 | 0.54 ± 0.15 |

## Mean RTT (ms)

Each run's mean of its pings. A few late replies pull the mean up (see the median and the minimum below).

| Protocol | none | good | normal | bad |
|---|---|---|---|---|
| Plain | 0.1 ± 0.0 | 22.0 ± 1.7 | 101.7 ± 0.9 | 306.4 ± 5.6 |
| Mini VPN | 1.2 ± 0.1 | 22.4 ± 0.1 | 106.0 ± 2.1 | 306.4 ± 3.4 |
| WireGuard | 0.6 ± 0.0 | 22.1 ± 0.1 | 102.5 ± 0.6 | 302.5 ± 0.3 |
| OpenVPN | 0.5 ± 0.0 | 22.3 ± 0.5 | 104.2 ± 1.8 | 304.8 ± 3.5 |
| GRE | 0.1 ± 0.0 | 21.4 ± 0.6 | 100.9 ± 1.3 | 301.0 ± 2.4 |

## Median RTT (ms)

Each run's median of its pings: much less moved by a few spikes than the mean.

| Protocol | none | good | normal | bad |
|---|---|---|---|---|
| Plain | 0.1 ± 0.0 | 21.8 ± 1.3 | 102.0 ± 1.0 | 304.0 ± 3.5 |
| Mini VPN | 1.1 ± 0.1 | 22.3 ± 0.1 | 106.2 ± 2.5 | 307.3 ± 3.1 |
| WireGuard | 0.6 ± 0.0 | 22.1 ± 0.2 | 101.8 ± 0.8 | 301.8 ± 2.0 |
| OpenVPN | 0.5 ± 0.0 | 22.5 ± 0.6 | 104.3 ± 1.5 | 305.3 ± 5.1 |
| GRE | 0.1 ± 0.0 | 21.3 ± 0.6 | 100.5 ± 0.8 | 303.3 ± 2.1 |

## Minimum RTT (ms)

Each run's fastest ping: the closest to the delay the network adds with nothing in the way.

| Protocol | none | good | normal | bad |
|---|---|---|---|---|
| Plain | 0.0 ± 0.0 | 17.2 ± 0.5 | 83.4 ± 1.8 | 246.0 ± 2.0 |
| Mini VPN | 0.5 ± 0.0 | 18.4 ± 0.6 | 84.1 ± 1.6 | 255.7 ± 2.1 |
| WireGuard | 0.3 ± 0.0 | 17.7 ± 0.8 | 84.8 ± 1.9 | 251.0 ± 2.6 |
| OpenVPN | 0.3 ± 0.0 | 18.0 ± 0.1 | 86.5 ± 1.8 | 251.0 ± 4.0 |
| GRE | 0.1 ± 0.0 | 17.5 ± 0.5 | 85.5 ± 1.9 | 248.0 ± 4.0 |

## Packet loss (%)

| Protocol | none | good | normal | bad |
|---|---|---|---|---|
| Plain | 0.00 ± 0.00 | 0.00 ± 0.00 | 2.33 ± 2.31 | 9.00 ± 2.00 |
| Mini VPN | 0.00 ± 0.00 | 0.00 ± 0.00 | 2.00 ± 1.00 | 12.67 ± 5.86 |
| WireGuard | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.67 ± 1.15 | 11.33 ± 5.77 |
| OpenVPN | 0.00 ± 0.00 | 0.00 ± 0.00 | 2.00 ± 1.00 | 12.00 ± 1.73 |
| GRE | 0.00 ± 0.00 | 0.00 ± 0.00 | 2.67 ± 0.58 | 9.67 ± 1.15 |
