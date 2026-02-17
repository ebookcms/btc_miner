"""
Rukka BTC Miner CPU v2.0 - SOLO MINING ENHANCED
================================================

New Features:
- Real-time statistics dashboard (hashrate, estimated time, best share)
- Benchmark mode (test performance without mining)
- Watchdog monitoring (auto-restart on stalls)
- JSON stats logging with rotation
- Multiple configuration profiles
- Telegram/Discord webhook notifications
- CPU affinity control
- Enhanced RPC failover
- Donation system (optional dev fee)
- Test mode (validate setup)

Usage:
    python btc_minerV2.py --workers 4
    python btc_minerV2.py --benchmark
    python btc_minerV2.py --config custom.cfg --stats-file stats.json
    btc_minerV2
"""

import os
import sys
import hashlib
import json
import requests
import configparser
import time
import struct
import random
import multiprocessing as mp
import ctypes
import platform
import argparse
import logging
import signal
import threading
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor, as_completed
from colorama import init, Fore, Style
from pathlib import Path

try:
    import winsound
except ImportError:
    winsound = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

init()

# ============================================================================
# VERSION INFO
# ============================================================================
VERSION = "2.0.0"
AUTHOR = "Rukka Miner Team"
DONATION_BTC = "bc1q54p0qum0c2zf00shkszf6v9xvsdg6aaj0cjvx2"

# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Rukka BTC Miner CPU v2.0 - Solo Mining Enhanced',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --workers 4                    # Start with 4 workers
  {sys.argv[0]} --benchmark --duration 60      # Benchmark for 60 seconds
  {sys.argv[0]} --config pool.cfg --quiet      # Use custom config, minimal output
  {sys.argv[0]} --test-mode                    # Validate setup without mining
  
Donations: {DONATION_BTC}
        """
    )
    
    parser.add_argument('-w', '--workers', type=int, 
                        help='Number of workers (default: auto)')
    parser.add_argument('-c', '--config', default='data.cfg',
                        help='Configuration file (default: data.cfg)')
    parser.add_argument('-b', '--benchmark', action='store_true',
                        help='Benchmark mode (no RPC required)')
    parser.add_argument('-d', '--duration', type=int, default=300,
                        help='Benchmark duration in seconds (default: 300)')
    parser.add_argument('--stats-file', default='mining_stats.json',
                        help='JSON statistics file (default: mining_stats.json)')
    parser.add_argument('--stats-interval', type=int, default=60,
                        help='Statistics save interval in seconds (default: 60)')
    parser.add_argument('--webhook', 
                        help='Webhook URL for notifications (Discord/Slack)')
    parser.add_argument('--cpu-affinity', action='store_true',
                        help='Pin workers to specific CPU cores')
    parser.add_argument('--donation', type=float, default=0.0,
                        help='Donation percentage 0-5 (default: 0)')
    parser.add_argument('-t', '--test-mode', action='store_true',
                        help='Test configuration and exit')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose debugging output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    return parser.parse_args()

ARGS = parse_arguments()

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging():
    """Configure logging system."""
    level = logging.DEBUG if ARGS.verbose else (logging.WARNING if ARGS.quiet else logging.INFO)
    
    log_format = '%(asctime)s | %(levelname)-8s | %(message)s'
    logging.basicConfig(level=level, format=log_format, datefmt='%Y-%m-%d %H:%M:%S')
    
    # File handler for persistent logs
    file_handler = logging.FileHandler('miner.log')
    file_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(file_handler)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ============================================================================
# STATISTICS TRACKER
# ============================================================================

class MiningStats:
    """Tracks mining statistics and exports to JSON."""
    
    def __init__(self, filename='mining_stats.json'):
        self.filename = filename
        self.session_start = time.time()
        self.total_hashes = 0
        self.session_hashes = 0
        self.blocks_found = 0
        self.best_share_difficulty = 0.0
        self.current_hashrate = 0.0
        self.avg_hashrate = 0.0
        self.peak_hashrate = 0.0
        self.rejected_shares = 0
        self.stale_shares = 0
        self.worker_restarts = 0
        self.last_save = time.time()
        self.load_stats()
    
    def add_hashes(self, count):
        """Add hashes to total."""
        self.total_hashes += count
        self.session_hashes += count
    
    def update_hashrate(self, hashrate_mhs):
        """Update current hashrate metrics."""
        self.current_hashrate = hashrate_mhs
        elapsed = time.time() - self.session_start
        if elapsed > 0:
            self.avg_hashrate = (self.session_hashes / elapsed) / 1e6
        if hashrate_mhs > self.peak_hashrate:
            self.peak_hashrate = hashrate_mhs
    
    def add_block(self, height, reward):
        """Record found block."""
        self.blocks_found += 1
        logger.info(f"Block found: #{height} - Reward: {reward/1e8:.8f} BTC")
    
    def update_best_share(self, difficulty):
        """Update best share difficulty."""
        if difficulty > self.best_share_difficulty:
            self.best_share_difficulty = difficulty
    
    def get_uptime(self):
        """Get session uptime."""
        return timedelta(seconds=int(time.time() - self.session_start))
    
    def estimate_time_to_block(self, network_difficulty):
        """Estimate time to find a block at current hashrate."""
        if self.avg_hashrate <= 0:
            return "Unknown"
        # Rough estimation: network_difficulty * 2^32 / hashrate
        seconds = (network_difficulty * 2**32) / (self.avg_hashrate * 1e6)
        if seconds > 86400 * 365:
            return f"{seconds/86400/365:.1f} years"
        elif seconds > 86400:
            return f"{seconds/86400:.1f} days"
        elif seconds > 3600:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/60:.1f} minutes"
    
    def to_dict(self):
        """Export statistics as dictionary."""
        return {
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': int(time.time() - self.session_start),
            'total_hashes': self.total_hashes,
            'session_hashes': self.session_hashes,
            'blocks_found': self.blocks_found,
            'best_share_difficulty': self.best_share_difficulty,
            'current_hashrate_mhs': round(self.current_hashrate, 2),
            'average_hashrate_mhs': round(self.avg_hashrate, 2),
            'peak_hashrate_mhs': round(self.peak_hashrate, 2),
            'rejected_shares': self.rejected_shares,
            'stale_shares': self.stale_shares,
            'worker_restarts': self.worker_restarts
        }
    
    def save(self, force=False):
        """Save statistics to JSON file."""
        if not force and time.time() - self.last_save < ARGS.stats_interval:
            return
        
        try:
            data = self.to_dict()
            # Keep history if file exists
            if os.path.exists(self.filename):
                try:
                    with open(self.filename, 'r') as f:
                        old_data = json.load(f)
                        if 'history' not in old_data:
                            old_data['history'] = []
                        # Add current to history every 10 saves
                        if len(old_data['history']) > 100:
                            old_data['history'].pop(0)
                        if force or int(time.time()) % 600 == 0:  # Every 10 min in history
                            old_data['history'].append({
                                'timestamp': datetime.now().isoformat(),
                                'hashrate': data['average_hashrate_mhs']
                            })
                        data['history'] = old_data['history']
                except:
                    pass
            
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.last_save = time.time()
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")
    
    def load_stats(self):
        """Load previous total hashes from file."""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    self.total_hashes = data.get('total_hashes', 0)
            except:
                pass

# Global statistics instance
STATS = MiningStats(ARGS.stats_file)

# ============================================================================
# WEBHOOK NOTIFICATIONS
# ============================================================================

def send_notification(message, priority='normal'):
    """Send webhook notification if configured."""
    if not ARGS.webhook:
        return
    
    try:
        payload = {
            'content': f"🚀 **Rukka Miner v{VERSION}**\n{message}",
            'username': 'Rukka Miner Bot'
        }
        
        if 'discord' in ARGS.webhook:
            requests.post(ARGS.webhook, json=payload, timeout=5)
        elif 'slack' in ARGS.webhook:
            requests.post(ARGS.webhook, json={'text': message}, timeout=5)
        else:
            requests.post(ARGS.webhook, json=payload, timeout=5)
            
        logger.info(f"Notification sent: {message[:50]}...")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

# ============================================================================
# WATCHDOG MONITOR
# ============================================================================

class Watchdog(threading.Thread):
    """Monitors mining health and restarts if stalled."""
    
    def __init__(self, timeout=60):
        super().__init__(daemon=True)
        self.timeout = timeout
        self.last_activity = time.time()
        self.running = True
        self.check_interval = 10
    
    def update(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()
    
    def run(self):
        """Watchdog loop."""
        while self.running:
            time.sleep(self.check_interval)
            inactive = time.time() - self.last_activity
            
            if inactive > self.timeout:
                logger.error(f"Watchdog: No activity for {inactive:.0f}s, triggering restart!")
                STATS.worker_restarts += 1
                # Signal main thread to restart
                os.kill(os.getpid(), signal.SIGTERM)
    
    def stop(self):
        self.running = False

# ============================================================================
# DETECTION AND LOADING OF C LIBRARY (sha256.dll / sha256.so)
# ============================================================================

_sha256_lib = None
_lib_path = None

def _load_sha256_library():
    """Try to load the compiled C library (sha256.dll or sha256.so)"""
    global _sha256_lib, _lib_path
    
    system = platform.system()
    if system == "Windows":
        lib_names = ["sha256.dll", "sha256_cpu.dll", "libsha256.dll"]
    elif system == "Darwin":
        lib_names = ["sha256.so", "sha256.dylib", "libsha256.so"]
    else:  # Linux
        lib_names = ["sha256.so", "sha256_cpu.so", "libsha256.so"]
    
    search_paths = [os.getcwd(), os.path.dirname(os.path.abspath(__file__)), "."]
    
    for path in search_paths:
        for name in lib_names:
            full_path = os.path.join(path, name)
            if os.path.exists(full_path):
                try:
                    lib = ctypes.CDLL(full_path)
                    lib.mine_range.argtypes = [
                        ctypes.c_char_p,
                        ctypes.c_char_p,
                        ctypes.c_uint32,
                        ctypes.c_uint32
                    ]
                    lib.mine_range.restype = ctypes.c_int64
                    
                    # Quick validation test
                    test_header = bytes(76)
                    test_target = b'\xff' * 32
                    result = lib.mine_range(test_header, test_target, 0, 100)
                    
                    _sha256_lib = lib
                    _lib_path = full_path
                    #logger.info(f"C acceleration loaded: {name}")
                    return True
                except Exception as e:
                    logger.debug(f"Failed to load {name}: {e}")
                    continue
    return False

_has_accel = _load_sha256_library()

# ============================================================================
# CONFIGURATION
# ============================================================================

def load_config():
    """Load and validate configuration."""
    config = configparser.ConfigParser()
    
    if not os.path.exists(ARGS.config):
        logger.error(f"Configuration file not found: {ARGS.config}")
        print(f"{Fore.RED}ERROR: Config file '{ARGS.config}' not found!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Create it with:{Style.RESET_ALL}")
        print("""
[CONFIG]
rpcPort = 8332
rpcUser = bitcoin
rpcPassword = password
rpcIp = 127.0.0.1
btcaddr = your_btc_address_here
poolname = RukkaMiner
        """)
        sys.exit(1)
    
    config.read(ARGS.config)
    
    required = ['rpcPort', 'rpcUser', 'rpcPassword', 'rpcIp', 'btcaddr', 'poolname']
    missing = []
    
    for key in required:
        if not config.has_option('CONFIG', key):
            missing.append(key)
    
    if missing:
        logger.error(f"Missing config options: {missing}")
        print(f"{Fore.RED}ERROR: Missing options in config: {', '.join(missing)}{Style.RESET_ALL}")
        sys.exit(1)
    
    return config

config = load_config()
rpcPort = config.get('CONFIG', 'rpcPort')
rpcUser = config.get('CONFIG', 'rpcUser')
rpcPassword = config.get('CONFIG', 'rpcPassword')
rpcIp = config.get('CONFIG', 'rpcIp')
btc_address = config.get('CONFIG', 'btcaddr')
pool_name = config.get('CONFIG', 'poolname')

serverURL = f'http://{rpcUser}:{rpcPassword}@{rpcIp}:{rpcPort}'
headers_rpc = {'content-type': 'application/json'}

# ============================================================================
# SETTINGS
# ============================================================================
NUM_WORKERS = ARGS.workers if ARGS.workers else 10
NONCES_PER_WORKER = 200_000
NEW_BLOCK_CHECK_INTERVAL = 5
TEMPLATE_REFRESH_SECONDS = 30
MAX_BLOCK_WEIGHT = 3_996_000
MAX_BLOCK_SIGOPS = 80_000
WATCHDOG_TIMEOUT = 120

# ============================================================================
# BENCHMARK MODE
# ============================================================================

def run_benchmark(duration_seconds=300):
    """Run hashrate benchmark without RPC."""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"  BENCHMARK MODE - {duration_seconds}s")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    cpu_name = platform.processor() or "Unknown CPU"
    print(f"CPU: {cpu_name}")
    print(f"Cores: {mp.cpu_count()}")
    print(f"Workers: {NUM_WORKERS}")
    print(f"Acceleration: {'C/DLL' if _has_accel else 'Python/hashlib'}")
    print(f"\n{Fore.YELLOW}Running benchmark... Please wait...{Style.RESET_ALL}\n")
    
    test_header = bytes(76)
    test_target = b'\x00' + b'\xff' * 31  # Difficulty 1
    total_hashes = 0
    start_time = time.time()
    chunks_per_batch = NUM_WORKERS
    
    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        while time.time() - start_time < duration_seconds:
            futures = []
            for i in range(chunks_per_batch):
                nonce_start = random.randint(0, 0x7FFFFFFF)
                args = (test_header, test_target, nonce_start, nonce_start + NONCES_PER_WORKER)
                futures.append(executor.submit(_cpu_mine_chunk, args))
            
            t0 = time.time()
            done = 0
            for future in as_completed(futures):
                future.result()
                done += 1
            
            elapsed = time.time() - t0
            hashes = chunks_per_batch * NONCES_PER_WORKER
            total_hashes += hashes
            hashrate = hashes / elapsed / 1e6 if elapsed > 0 else 0
            
            progress = (time.time() - start_time) / duration_seconds * 100
            print(f"Progress: {progress:.1f}% | Hashrate: {hashrate:.2f} MH/s", end='\r')
    
    total_time = time.time() - start_time
    avg_hashrate = (total_hashes / total_time) / 1e6
    
    print(f"\n\n{Fore.GREEN}{'='*70}")
    print(f"BENCHMARK RESULTS")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f"Total Time:     {total_time:.2f} seconds")
    print(f"Total Hashes:   {total_hashes:,}")
    print(f"Average Speed:  {Fore.CYAN}{avg_hashrate:.2f} MH/s{Style.RESET_ALL}")
    print(f"Per Worker:     {avg_hashrate/NUM_WORKERS:.2f} MH/s")
    print(f"{'='*70}")
    
    # Save benchmark results
    bench_data = {
        'timestamp': datetime.now().isoformat(),
        'cpu': cpu_name,
        'workers': NUM_WORKERS,
        'acceleration': 'C' if _has_accel else 'Python',
        'avg_hashrate_mhs': round(avg_hashrate, 2),
        'total_hashes': total_hashes
    }
    
    with open('benchmark_result.json', 'w') as f:
        json.dump(bench_data, f, indent=2)
    
    print(f"\nResults saved to benchmark_result.json")

# ============================================================================
# CORE FUNCTIONS (from previous version with improvements)
# ============================================================================

# ============================================================================
# WORKER — with C acceleration support (CLEAN SHUTDOWN VERSION)
# ============================================================================

def _cpu_mine_chunk(args):
    """
    CPU Worker. Tests nonces [start, end).
    Uses C library if available, otherwise hashlib.
    Returns nonce or None.
    """
    # Suppress KeyboardInterrupt in worker processes (prevents messy tracebacks)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    try:
        header_76, target_bytes, nonce_start, nonce_end = args
        
        # Set CPU affinity if requested
        if ARGS.cpu_affinity and HAS_PSUTIL:
            try:
                p = psutil.Process()
                cpu_id = (nonce_start // NONCES_PER_WORKER) % mp.cpu_count()
                p.cpu_affinity([cpu_id])
            except:
                pass
        
        # Try C library first (faster)
        if _sha256_lib is not None:
            count = nonce_end - nonce_start
            result = _sha256_lib.mine_range(header_76, target_bytes, nonce_start, count)
            if result >= 0:
                return result
            return None
        
        # Fallback to Python
        sha256 = hashlib.sha256
        pack = struct.pack
        for nonce in range(nonce_start, nonce_end):
            header = header_76 + pack("<I", nonce)
            h = sha256(sha256(header).digest()).digest()
            if h[::-1] < target_bytes:
                return nonce
        return None
        
    except KeyboardInterrupt:
        # Clean exit without traceback
        # Final stats
        et = time.time() - t_global
        print(f"\n{'='*70}")
        print(f"{Fore.CYAN}SESSION ENDED{Style.RESET_ALL}")
        print(f"  Duration:  {timedelta(seconds=int(et))}")
        print(f"  Hashes:    {STATS.session_hashes:,}")
        print(f"  Avg Speed: {STATS.avg_hashrate:.2f} MH/s")
        print(f"  Blocks:    {STATS.blocks_found}")
        print(f"{'='*70}")
        print(f"{Fore.GREEN}Thank you for supporting Rukka Miner!{Style.RESET_ALL}")
        print(f"Donations: {DONATION_BTC}")
        return None
    except Exception:
        return None

# ============================================================================
# MAIN MINING LOOP (CLEAN SHUTDOWN)
# ============================================================================

# ============================================================================
# WORKER — with C acceleration support (CLEAN SHUTDOWN VERSION)
# ============================================================================

def _cpu_mine_chunk(args):
    """
    CPU Worker. Tests nonces [start, end).
    Uses C library if available, otherwise hashlib.
    Returns nonce or None.
    """
    # Suppress KeyboardInterrupt in worker processes (prevents messy tracebacks)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    try:
        header_76, target_bytes, nonce_start, nonce_end = args
        
        # Set CPU affinity if requested
        if ARGS.cpu_affinity and HAS_PSUTIL:
            try:
                p = psutil.Process()
                cpu_id = (nonce_start // NONCES_PER_WORKER) % mp.cpu_count()
                p.cpu_affinity([cpu_id])
            except:
                pass
        
        # Try C library first (faster)
        if _sha256_lib is not None:
            count = nonce_end - nonce_start
            result = _sha256_lib.mine_range(header_76, target_bytes, nonce_start, count)
            if result >= 0:
                return result
            return None
        
        # Fallback to Python
        sha256 = hashlib.sha256
        pack = struct.pack
        for nonce in range(nonce_start, nonce_end):
            header = header_76 + pack("<I", nonce)
            h = sha256(sha256(header).digest()).digest()
            if h[::-1] < target_bytes:
                return nonce
        return None
        
    except KeyboardInterrupt:
        # Clean exit without traceback
        return None
    except Exception:
        return None

# ============================================================================
# MAIN MINING LOOP (CLEAN SHUTDOWN)
# ============================================================================

def signal_handler(signum, frame):
    """Handle shutdown gracefully - suppresses all worker noise."""
    print(f"\n{Fore.YELLOW}⚠ Stopping miner... Please wait.{Style.RESET_ALL}")
    
    # Force kill our process group to stop all workers immediately
    # This prevents the messy tracebacks from worker processes
    try:
        if platform.system() == "Windows":
            # Windows: Terminate all child processes
            if HAS_PSUTIL:
                parent = psutil.Process(os.getpid())
                for child in parent.children(recursive=True):
                    try:
                        child.terminate()
                    except:
                        pass
        else:
            # Unix: Send SIGTERM to process group
            os.killpg(0, signal.SIGTERM)
    except:
        pass
    
    # Save stats one last time
    try:
        STATS.save(force=True)
    except:
        pass
    
    # Exit cleanly
    sys.exit(0)

def main():
    """Main mining loop with clean shutdown."""
    global NUM_WORKERS
    
    # Set process group for Unix (allows killing all children at once)
    if platform.system() != "Windows":
        try:
            os.setpgrp()
        except:
            pass
    
    # Setup signal handlers in main process only
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # ... rest of your setup code ...
    
    executor = ProcessPoolExecutor(max_workers=NUM_WORKERS)
    
    try:
        while True:
            # ... your mining loop ...
            pass
            
    except KeyboardInterrupt:
        # This should be caught by signal handler, but just in case
        signal_handler(None, None)
        
    finally:
        # Ultra-clean shutdown
        print(f"{Fore.CYAN}Cleaning up workers...{Style.RESET_ALL}")
        try:
            # Cancel pending futures
            executor.shutdown(wait=False, cancel_futures=True)
        except:
            pass
        
        # Force kill any remaining processes
        if HAS_PSUTIL:
            try:
                parent = psutil.Process(os.getpid())
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except:
                        pass
            except:
                pass
        
        STATS.save(force=True)
        print(f"{Fore.GREEN}✓ Shutdown complete{Style.RESET_ALL}")

def main():
    """Main mining loop with clean shutdown."""
    global NUM_WORKERS
    
    # Set process group for Unix (allows killing all children at once)
    if platform.system() != "Windows":
        try:
            os.setpgrp()
        except:
            pass
    
    # Setup signal handlers in main process only
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # ... rest of your setup code ...
    
    executor = ProcessPoolExecutor(max_workers=NUM_WORKERS)
    
    try:
        while True:
            # ... your mining loop ...
            pass
            
    except KeyboardInterrupt:
        # This should be caught by signal handler, but just in case
        signal_handler(None, None)
        
    finally:
        # Ultra-clean shutdown
        print(f"{Fore.CYAN}Cleaning up workers...{Style.RESET_ALL}")
        try:
            # Cancel pending futures
            executor.shutdown(wait=False, cancel_futures=True)
        except:
            pass
        
        # Force kill any remaining processes
        if HAS_PSUTIL:
            try:
                parent = psutil.Process(os.getpid())
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except:
                        pass
            except:
                pass
        
        STATS.save(force=True)
        print(f"{Fore.GREEN}✓ Shutdown complete{Style.RESET_ALL}")

def rpc_call(method, params=[], retries=3):
    """RPC call with retry logic."""
    payload = json.dumps({"jsonrpc": "2.0", "id": "miner", "method": method, "params": params})
    
    for attempt in range(retries):
        try:
            response = requests.post(serverURL, headers=headers_rpc, data=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                if result.get('error'):
                    logger.error(f"RPC Error: {result['error']}")
                    return None
                return result.get('result')
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logger.error(f"RPC failed after {retries} attempts: {e}")
    return None

def test_connection():
    """Test Bitcoin Core connection."""
    if ARGS.quiet:
        return rpc_call('getblockchaininfo') is not None
    
    print(f"{Fore.CYAN}Testing connection to Bitcoin Core...{Style.RESET_ALL}")
    info = rpc_call('getblockchaininfo')
    if info is None:
        print(f"{Fore.RED}✗ Connection failed!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Check: Bitcoin Core running? RPC enabled? Config correct?{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.GREEN}✓ Connected!{Style.RESET_ALL}")
    print(f"  Chain:    {info.get('chain')}")
    print(f"  Blocks:   {info.get('blocks'):,}")
    print(f"  Difficulty: {info.get('difficulty', 0):.4e}")
    print(f"  Headers:  {info.get('headers', 0):,}")
    
    if info.get('chain') == 'main':
        print(f"{Fore.YELLOW}  ⚠ Mining on MAINNET{Style.RESET_ALL}")
    
    return True

def validate_setup():
    """Validate entire setup without mining."""
    print(f"\n{Fore.CYAN}TEST MODE - Validating Setup...{Style.RESET_ALL}\n")
    
    checks = []
    
    # Check 1: Config
    print("1. Configuration file... ", end='')
    if os.path.exists(ARGS.config):
        print(f"{Fore.GREEN}OK{Style.RESET_ALL}")
        checks.append(True)
    else:
        print(f"{Fore.RED}FAIL{Style.RESET_ALL}")
        checks.append(False)
    
    # Check 2: RPC Connection
    print("2. RPC Connection... ", end='')
    if test_connection():
        print(f"{Fore.GREEN}OK{Style.RESET_ALL}")
        checks.append(True)
    else:
        print(f"{Fore.RED}FAIL{Style.RESET_ALL}")
        checks.append(False)
    
    # Check 3: Address validation
    print("3. BTC Address... ", end='')
    spk = address_to_scriptpubkey(btc_address)
    if spk:
        print(f"{Fore.GREEN}OK{Style.RESET_ALL} ({btc_address[:20]}...)")
        checks.append(True)
    else:
        print(f"{Fore.RED}FAIL{Style.RESET_ALL}")
        checks.append(False)
    
    # Check 4: C Library
    print("4. C Acceleration... ", end='')
    if _has_accel:
        print(f"{Fore.GREEN}OK{Style.RESET_ALL} ({os.path.basename(_lib_path)})")
    else:
        print(f"{Fore.YELLOW}WARNING{Style.RESET_ALL} (Using Python fallback)")
    checks.append(True)  # Not critical
    
    # Check 5: Workers
    print("5. Worker processes... ", end='')
    try:
        with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            result = executor.submit(lambda: True).result(timeout=5)
            print(f"{Fore.GREEN}OK{Style.RESET_ALL} ({NUM_WORKERS} workers)")
            checks.append(True)
    except Exception as e:
        print(f"{Fore.RED}FAIL{Style.RESET_ALL} ({e})")
        checks.append(False)
    
    print(f"\n{Fore.CYAN}Setup validation: {sum(checks)}/{len(checks)} checks passed{Style.RESET_ALL}")
    
    if all(checks[:3]):  # First 3 must pass
        print(f"{Fore.GREEN}Ready to mine!{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}Fix errors before mining!{Style.RESET_ALL}")
        return False

# Helper functions (same as v1 with logging added)
def address_to_scriptpubkey(address):
    """Convert address to scriptPubKey."""
    if address.startswith(('bc1', 'tb1', 'bcrt1')):
        result = bech32_decode(address)
        if result:
            return result
    try:
        conn = rpc_call('validateaddress', [address])
        if conn and conn.get('isvalid'):
            return conn.get('scriptPubKey')
    except Exception as e:
        logger.error(f"Address validation error: {e}")
    return None

def bech32_decode(bech):
    """Bech32 decoding."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if bech.lower() != bech and bech.upper() != bech:
        return None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None
    data = [charset.find(x) for x in bech[pos+1:]]
    if any(x < 0 for x in data):
        return None
    values, bits_acc, value = [], 0, 0
    for d in data[1:-6]:
        value = (value << 5) | d
        bits_acc += 5
        if bits_acc >= 8:
            bits_acc -= 8
            values.append((value >> bits_acc) & 0xff)
            value &= (1 << bits_acc) - 1
    if bits_acc >= 5 or value != 0:
        return None
    wv = data[0]
    wp = bytes(values)
    op = 0x00 if wv == 0 else (0x50 + wv)
    return (bytes([op, len(wp)]) + wp).hex()

def get_subsidy(height):
    """Calculate block subsidy."""
    halvings = height // 210_000
    if halvings >= 64:
        return 0
    return (50 * 100_000_000) >> halvings

def encode_varint(n):
    """Encode integer as varint."""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def hash_pair(a, b):
    """Hash two values together."""
    if isinstance(a, bytes): a = a.decode()
    if isinstance(b, bytes): b = b.decode()
    ba = bytes.fromhex(a)[::-1]
    bb = bytes.fromhex(b)[::-1]
    h = hashlib.sha256(hashlib.sha256(ba + bb).digest()).digest()
    return h[::-1].hex()

def merkle_root(hashes):
    """Calculate merkle root."""
    if not hashes:
        return '0' * 64
    hashes = [h.decode() if isinstance(h, bytes) else h for h in hashes]
    if len(hashes) == 1:
        return hashes[0]
    while len(hashes) > 1:
        new_level = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                new_level.append(hash_pair(hashes[i], hashes[i + 1]))
            else:
                new_level.append(hash_pair(hashes[i], hashes[i]))
        hashes = new_level
    return hashes[0]

def calculate_witness_commitment(wtxid_list):
    """Calculate witness commitment."""
    wrv = bytes(32)
    w_root = merkle_root(wtxid_list)
    cd = bytes.fromhex(w_root)[::-1] + wrv
    ch = hashlib.sha256(hashlib.sha256(cd).digest()).digest()
    return (bytes.fromhex('6a24aa21a9ed') + ch).hex()

def create_coinbase_tx(height, coinbase_value_sat, scriptpubkey_hex,
                       message, extranonce, witness_commitment_hex=None, donation_percent=0):
    """Create coinbase transaction with optional donation."""
    if height == 0:
        h_bytes = b'\x00'
    elif height <= 0xFF:
        h_bytes = height.to_bytes(1, 'little')
    elif height <= 0xFFFF:
        h_bytes = height.to_bytes(2, 'little')
    elif height <= 0xFFFFFF:
        h_bytes = height.to_bytes(3, 'little')
    else:
        h_bytes = height.to_bytes(4, 'little')
    
    en_bytes = extranonce.to_bytes(8, 'little')
    msg_bytes = message.encode('utf-8')
    scriptsig = bytes([len(h_bytes)]) + h_bytes + en_bytes + bytes([len(msg_bytes)]) + msg_bytes
    
    if len(scriptsig) > 100:
        max_msg = 100 - (1 + len(h_bytes) + 8 + 1)
        msg_bytes = msg_bytes[:max(0, max_msg)]
        scriptsig = bytes([len(h_bytes)]) + h_bytes + en_bytes + bytes([len(msg_bytes)]) + msg_bytes
    
    # Main output
    outputs = [{"value_sat": coinbase_value_sat, "scriptPubKey": scriptpubkey_hex}]
    
    # Donation output if enabled
    if donation_percent > 0 and donation_percent <= 5:
        donation_amount = int(coinbase_value_sat * (donation_percent / 100))
        if donation_amount > 1000:  # Min 1000 satoshis
            donation_spk = address_to_scriptpubkey(DONATION_BTC)
            if donation_spk:
                outputs.append({"value_sat": donation_amount, "scriptPubKey": donation_spk})
                # Reduce main output
                outputs[0]["value_sat"] -= donation_amount
    
    if witness_commitment_hex:
        outputs.append({"value_sat": 0, "scriptPubKey": witness_commitment_hex})
    
    return {"version": 2, "scriptsig_hex": scriptsig.hex(),
            "sequence": 0xffffffff, "outputs": outputs, "locktime": 0}

def serialize_coinbase_legacy(cb):
    """Serialize coinbase transaction (legacy)."""
    r = struct.pack('<I', cb['version'])
    r += b'\x01' + bytes(32) + struct.pack('<I', 0xffffffff)
    ss = bytes.fromhex(cb['scriptsig_hex'])
    r += encode_varint(len(ss)) + ss + struct.pack('<I', cb['sequence'])
    r += encode_varint(len(cb['outputs']))
    for out in cb['outputs']:
        r += out['value_sat'].to_bytes(8, 'little')
        spk = bytes.fromhex(out['scriptPubKey'])
        r += encode_varint(len(spk)) + spk
    r += struct.pack('<I', cb['locktime'])
    return r

def serialize_coinbase_segwit(cb):
    """Serialize coinbase transaction (segwit)."""
    r = struct.pack('<I', cb['version'])
    r += b'\x00\x01'  # Segwit marker and flag
    r += b'\x01' + bytes(32) + struct.pack('<I', 0xffffffff)
    ss = bytes.fromhex(cb['scriptsig_hex'])
    r += encode_varint(len(ss)) + ss + struct.pack('<I', cb['sequence'])
    r += encode_varint(len(cb['outputs']))
    for out in cb['outputs']:
        r += out['value_sat'].to_bytes(8, 'little')
        spk = bytes.fromhex(out['scriptPubKey'])
        r += encode_varint(len(spk)) + spk
    r += b'\x01\x20' + bytes(32)  # Witness
    r += struct.pack('<I', cb['locktime'])
    return r

def coinbase_txid(cb):
    """Calculate coinbase txid."""
    ser = serialize_coinbase_legacy(cb)
    return hashlib.sha256(hashlib.sha256(ser).digest()).digest()[::-1].hex()

def select_transactions_from_template(template_txs, max_weight=MAX_BLOCK_WEIGHT):
    """Select transactions from template."""
    tx_by_index = {i + 1: tx for i, tx in enumerate(template_txs)}
    selected, selected_indices = [], set()
    total_weight, total_sigops, total_fee_sat = 1000, 0, 0

    def add_tx(idx):
        nonlocal total_weight, total_sigops, total_fee_sat
        if idx in selected_indices:
            return True
        tx = tx_by_index.get(idx)
        if tx is None:
            return False
        w, s = tx.get('weight', 0), tx.get('sigops', 0)
        if total_weight + w > max_weight or total_sigops + s > MAX_BLOCK_SIGOPS:
            return False
        for dep in tx.get('depends', []):
            if not add_tx(dep):
                return False
        if idx not in selected_indices:
            selected.append({'txid': tx['txid'], 'wtxid': tx.get('hash', tx['txid']),
                             'data': tx['data'], 'fee_sat': tx.get('fee', 0), 'weight': w})
            selected_indices.add(idx)
            total_weight += w
            total_sigops += s
            total_fee_sat += tx.get('fee', 0)
        return True

    for i in range(1, len(template_txs) + 1):
        if len(selected) >= 3500:
            break
        add_tx(i)
    return selected, total_fee_sat

def build_and_submit_block(header_complete, coinbase_tx, selected_txs,
                           target_bytes, block_height, coinbase_value_sat, hashrate):
    """Build and submit block to network."""
    h1 = hashlib.sha256(header_complete).digest()
    block_hash = hashlib.sha256(h1).digest()[::-1]
    
    if block_hash >= target_bytes:
        logger.error("Hash does not meet target!")
        return False
    
    nonce_found = struct.unpack('<I', header_complete[76:80])[0]
    
    print(f"\n{Fore.GREEN}{'='*70}")
    print(f"  *** BLOCK FOUND! ***")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f"  Hash:   {Fore.YELLOW}{block_hash.hex()}{Style.RESET_ALL}")
    print(f"  Height: {Fore.YELLOW}{block_height}{Style.RESET_ALL}")
    print(f"  Nonce:  {Fore.YELLOW}{nonce_found}{Style.RESET_ALL}")
    print(f"  Reward: {Fore.YELLOW}{coinbase_value_sat / 1e8:.8f} BTC{Style.RESET_ALL}")
    
    cb_hex = serialize_coinbase_segwit(coinbase_tx).hex()
    num_txs = 1 + len(selected_txs)
    block_hex = (header_complete.hex() + encode_varint(num_txs).hex() +
                 cb_hex + "".join(tx['data'] for tx in selected_txs))
    
    # Save block locally first
    block_file = f"block_{block_height}_{int(time.time())}.hex"
    try:
        with open(block_file, 'w') as f:
            f.write(block_hex)
        logger.info(f"Block saved to {block_file}")
    except Exception as e:
        logger.error(f"Failed to save block: {e}")
    
    # Submit via RPC
    try:
        result = rpc_call('submitblock', [block_hex])
        if result is None:
            print(f"\n{Fore.GREEN}  ✓✓✓ BLOCK ACCEPTED! ✓✓✓{Style.RESET_ALL}")
            STATS.add_block(block_height, coinbase_value_sat)
            
            # Notification
            msg = f"🎉 **BLOCK FOUND!**\nHeight: #{block_height}\nHash: {block_hash.hex()[:32]}...\nReward: {coinbase_value_sat/1e8:.8f} BTC"
            send_notification(msg, priority='high')
            
            # Save to blocks found log
            with open('blocks_found.txt', 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | #{block_height} | "
                        f"{coinbase_value_sat/1e8:.8f} BTC | {block_hash.hex()}\n")
            
            if winsound:
                winsound.Beep(1000, 2500)
            return True
        else:
            print(f"{Fore.RED}  ✗ Rejected: {result}{Style.RESET_ALL}")
            STATS.rejected_shares += 1
            return False
    except Exception as e:
        print(f"{Fore.RED}  Error: {e}{Style.RESET_ALL}")
        logger.error(f"Block submission error: {e}")
        return False

# ============================================================================
# MAIN MINING LOOP
# ============================================================================

def print_statistics(network_difficulty=1):
    """Print current statistics."""
    if ARGS.quiet:
        return
    
    uptime = STATS.get_uptime()
    eta = STATS.estimate_time_to_block(network_difficulty)
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"  STATISTICS")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f"  Uptime:           {uptime}")
    print(f"  Session Hashes:   {STATS.session_hashes:,}")
    print(f"  Total Hashes:     {STATS.total_hashes:,}")
    print(f"  Current Speed:    {Fore.CYAN}{STATS.current_hashrate:.2f} MH/s{Style.RESET_ALL}")
    print(f"  Average Speed:    {STATS.avg_hashrate:.2f} MH/s")
    print(f"  Peak Speed:       {STATS.peak_hashrate:.2f} MH/s")
    print(f"  Blocks Found:     {Fore.GREEN}{STATS.blocks_found}{Style.RESET_ALL}")
    print(f"  Best Share:       {STATS.best_share_difficulty:.2f}")
    print(f"  Est. Time/Block:  {eta}")
    print(f"{'='*70}\n")

def get_worker_count_interactive():
    """Get worker count if not provided via CLI."""
    if ARGS.workers:
        return ARGS.workers
    
    cpu_cores = mp.cpu_count()
    default_workers = min(cpu_cores, 10)
    
    print(f"{Fore.CYAN}Available CPU cores: {cpu_cores}{Style.RESET_ALL}")
    try:
        response = input(f"{Fore.CYAN}Enter number of workers [1-{cpu_cores*2}, default {default_workers}]: {Style.RESET_ALL}").strip()
        if not response:
            return default_workers
        count = int(response)
        if 1 <= count <= cpu_cores * 4:
            return count
        else:
            print(f"{Fore.YELLOW}Invalid range, using default: {default_workers}{Style.RESET_ALL}")
            return default_workers
    except ValueError:
        print(f"{Fore.YELLOW}Invalid input, using default: {default_workers}{Style.RESET_ALL}")
        return default_workers

def signal_handler(signum, frame):
    """Handle shutdown gracefully."""
    print(f"\n{Fore.YELLOW}Shutdown signal received, stopping...{Style.RESET_ALL}")
    STATS.save(force=True)
    sys.exit(0)

def main():
    """Main mining loop."""
    global NUM_WORKERS
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"\n{'='*70}")
    print(f"{Fore.CYAN}    Rukka BTC Miner CPU v{VERSION} - SOLO MINING{Style.RESET_ALL}")
    print(f"{'='*70}")
    
    # Handle benchmark mode
    if ARGS.benchmark:
        run_benchmark(ARGS.duration)
        return
    
    # Handle test mode
    if ARGS.test_mode:
        validate_setup()
        return
    
    # Get worker count
    NUM_WORKERS = get_worker_count_interactive()
    
    # System info
    cpu_name = platform.processor() or "Unknown CPU"
    print(f"  CPU:      {Fore.RED}{cpu_name}{Style.RESET_ALL}")
    print(f"  Cores:    {mp.cpu_count()}")
    print(f"  Workers:  {Fore.YELLOW}{NUM_WORKERS}{Style.RESET_ALL}")
    print(f"  Backend:  {Fore.GREEN if _has_accel else Fore.RED}{'C/DLL' if _has_accel else 'Python/hashlib'}{Style.RESET_ALL}")
    print(f"  Donation: {ARGS.donation}%")
    print(f"  Address:  {Fore.YELLOW}{btc_address[:25]}...{Style.RESET_ALL}")
    print(f"{'='*70}\n")
    
    # Test connection
    if not test_connection():
        print(f"{Fore.RED}Failed to connect. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Validate address
    my_spk = address_to_scriptpubkey(btc_address)
    if not my_spk:
        print(f"{Fore.RED}ERROR: Invalid BTC address!{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.GREEN}✓ Address validated{Style.RESET_ALL}\n")
    
    # Send startup notification
    send_notification(f"🚀 Miner started\nWorkers: {NUM_WORKERS}\nAddress: {btc_address[:20]}...")
    
    # Start watchdog
    watchdog = Watchdog(WATCHDOG_TIMEOUT)
    watchdog.start()
    
    print(f"{Fore.CYAN}Starting mining... Ctrl+C to stop{Style.RESET_ALL}\n")
    
    nonces_per_round = NONCES_PER_WORKER * NUM_WORKERS
    prev_fee = 0
    t_global = time.time()
    last_stats_time = time.time()
    
    executor = ProcessPoolExecutor(max_workers=NUM_WORKERS)
    
    try:
        while True:
            # Get block template
            tpl = rpc_call('getblocktemplate', [{"rules": ["segwit"]}])
            if tpl is None:
                logger.error("Failed to get block template, retrying in 10s...")
                time.sleep(10)
                continue
            
            # Parse template
            bh = tpl['height']
            ph = tpl['previousblockhash']
            ver = tpl['version']
            bits_int = int(tpl['bits'], 16)
            target_b = bytes.fromhex(tpl['target'])
            network_diff = tpl.get('difficulty', 1)
            min_t = tpl.get('mintime', tpl.get('curtime', int(time.time())))
            max_t = tpl.get('curtime', int(time.time())) + 7200
            cb_max = tpl['coinbasevalue']
            tpl_txs = tpl.get('transactions', [])
            
            if not ARGS.quiet:
                print(f"{'='*70}")
                print(f"{Fore.CYAN}NEW JOB - Block #{bh}{Style.RESET_ALL}")
                print(f"  Previous: ...{ph[9:]}")
                print(f"  Target:   {tpl['target'][:55]}...")
                print(f"  Txs:      {len(tpl_txs)} available")
            
            # Select transactions
            sel_txs, fee_sat = select_transactions_from_template(tpl_txs)
            sub_sat = get_subsidy(bh)
            cb_sat = min(sub_sat + fee_sat, cb_max)
            
            if not ARGS.quiet:
                print(f"  Selected: {len(sel_txs)} | Subsidy: {sub_sat/1e8:.8f} | Fees: \033[35m{fee_sat/1e8:.8f}{Style.RESET_ALL}")
                print(f"  Total Reward: {Fore.GREEN}{cb_sat/1e8:.8f} BTC{Style.RESET_ALL}")
            
            # Mining loop for this template
            en_base = random.randint(0, 0xFFFFFFFFFFFFFFFF)
            found = False
            t_tpl = time.time()
            rnd_h = 0
            t_rnd = time.time()
            n_off = 0
            
            for ei in range(200):
                if found:
                    break
                
                en = (en_base + ei) & 0xFFFFFFFFFFFFFFFF
                
                # Create coinbase (with donation if enabled)
                wl = ['0'*64] + [tx['wtxid'] for tx in sel_txs]
                wc = calculate_witness_commitment(wl)
                cb = create_coinbase_tx(bh, cb_sat, my_spk, pool_name, en, wc, ARGS.donation)
                cb_id = coinbase_txid(cb)
                mk = merkle_root([cb_id] + [tx['txid'] for tx in sel_txs])
                
                stale = False
                new_blk = False
                
                while n_off < 0xFFFFFFFF:
                    # Check for new block
                    if n_off % (NONCES_PER_WORKER * NEW_BLOCK_CHECK_INTERVAL) == 0:
                        chk = rpc_call('getbestblockhash')
                        if chk is None or chk != ph:
                            logger.info("New block detected on network")
                            new_blk = True
                            break
                        
                        # Refresh stats
                        if time.time() - last_stats_time > 60:
                            print_statistics(network_diff)
                            last_stats_time = time.time()
                            STATS.save()
                    
                    # Check template age
                    if time.time() - t_tpl >= TEMPLATE_REFRESH_SECONDS:
                        if not ARGS.quiet:
                            es = time.time() - t_rnd
                            print(f"\n{Fore.CYAN}Refreshing template... {rnd_h/es/1e6:.2f} MH/s{Style.RESET_ALL}")
                        stale = True
                        break
                    
                    # Build header
                    bt = max(min_t, min(int(time.time()), max_t))
                    hdr = (struct.pack("<I", ver) +
                           bytes.fromhex(ph)[::-1] +
                           bytes.fromhex(mk)[::-1] +
                           struct.pack("<I", bt) +
                           struct.pack("<I", bits_int))
                    
                    # Distribute work
                    chunks = []
                    for w in range(NUM_WORKERS):
                        ws = n_off + w * NONCES_PER_WORKER
                        we = min(ws + NONCES_PER_WORKER, 0xFFFFFFFF)
                        chunks.append((hdr, target_b, ws, we))
                    
                    # Mine
                    t0 = time.time()
                    futures = [executor.submit(_cpu_mine_chunk, c) for c in chunks]
                    
                    lottery = None
                    for fut in as_completed(futures):
                        r = fut.result()
                        if r is not None:
                            lottery = r
                            for f in futures:
                                f.cancel()
                            break
                    
                    # Calculate stats
                    dt = time.time() - t0
                    hr = nonces_per_round / dt / 1e6 if dt > 0 else 0
                    rnd_h += nonces_per_round
                    STATS.add_hashes(nonces_per_round)
                    STATS.update_hashrate(hr)
                    watchdog.update()
                    
                    # Progress display
                    if not ARGS.quiet:
                        print(f"  EN:{en&0xFFFF:04x} R:{n_off//nonces_per_round:>4} "
                              f"{hr:5.1f} MH/s (avg {STATS.avg_hashrate:.1f}) "
                              f"TXs:{len(sel_txs)} Fee:{fee_sat/1e8:.5f}", end='\r')
                    
                    # Check for solution
                    if lottery is not None:
                        hdr_full = hdr + struct.pack("<I", lottery)
                        ok = build_and_submit_block(hdr_full, cb, sel_txs, target_b, 
                                                     bh, cb_sat, hr)
                        if ok:
                            found = True
                            time.sleep(30)
                        break
                    
                    n_off += nonces_per_round
                
                if new_blk or stale:
                    break
            
            if not found and not ARGS.quiet:
                print()  # New line after progress
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        watchdog.stop()
        STATS.save(force=True)
        
        # Final stats
        et = time.time() - t_global
        print(f"\n{'='*70}")
        print(f"{Fore.CYAN}SESSION ENDED{Style.RESET_ALL}")
        print(f"  Duration:  {timedelta(seconds=int(et))}")
        print(f"  Hashes:    {STATS.session_hashes:,}")
        print(f"  Avg Speed: {STATS.avg_hashrate:.2f} MH/s")
        print(f"  Blocks:    {STATS.blocks_found}")
        print(f"{'='*70}")
        print(f"{Fore.GREEN}Thank you for supporting Rukka Miner!{Style.RESET_ALL}")
        print(f"Donations: {DONATION_BTC}")

if __name__ == '__main__':
    mp.freeze_support()
    main()