"""
Baseline fuzzer using pure boofuzz implementation.
This serves as the benchmark for ablation study comparison.
"""
import random
import string
import logging
import time
from typing import List, Optional, Dict, Any

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult


class BoofuzzMutators:
    """
    Mutation strategies from boofuzz for FTP fuzzing.
    These are the standard mutations used as baseline.
    """

    @staticmethod
    def string_mutators() -> List[str]:
        """Standard string mutation payloads."""
        mutations = [
            # Empty and whitespace
            "",
            " ",
            "\t",
            "\n",
            "\r\n",

            # Long strings
            "A" * 256,
            "A" * 1024,
            "A" * 4096,
            "A" * 10000,
            "A" * 65535,

            # Format strings
            "%s" * 10,
            "%n" * 10,
            "%x" * 10,
            "%s%s%s%s%s%s%s%s%s%s",
            "%n%n%n%n%n%n%n%n%n%n",
            "%.1024d",
            "%.65535s",

            # Special characters
            "\\",
            "/",
            ":",
            ";",
            "<",
            ">",
            "|",
            "?",
            "*",
            '"',
            "'",
            "`",

            # Null bytes
            "\x00",
            "\x00" * 10,
            "A\x00B",
            "\x00" * 256,

            # Binary data
            "\xff" * 10,
            "\x00\xff" * 100,

            # Integer overflow strings
            "-1",
            "0",
            "1",
            "65535",
            "65536",
            "2147483647",
            "2147483648",
            "-2147483648",
            "4294967295",
            "4294967296",

            # Path traversal
            "../",
            "..\\",
            "../" * 10,
            "..\\..\\..\\..\\",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            ".%2e/",
            "%252e%252e%252f",

            # Command injection
            "; ls",
            "| ls",
            "& ls",
            "` ls `",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",

            # Unicode
            "Ã" * 100,
            "\xc0\xae",  # Overlong encoding of .
            "\u0000",
            "\uffff",

            # SQL-like (CVE-2024-48651: ProFTPD mod_sql privilege escalation)
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'--",
            "root'--",
            "' OR ''='",
            "' UNION SELECT",
            "/**/",
            "1=1",
            "OR 1=1",
            "GID=0",
            "GROUP BY",

            # Template injection (CVE-2024-4040: CrushFTP SSTI/RCE)
            "${",
            "#{",
            "{{",
            "}}",
            "%{",
            "${env}",
            "{{config}}",
            "${system}",
            "<INCLUDE>",
            "sessions.obj",
            "users.xml",
            "${7*7}",
            "{{7*7}}",
            "${T(java.lang.Runtime)}",

            # Quote/backslash patterns (CVE-2023-51713: ProFTPD OOB Read DoS)
            "\\",
            "\\\\",
            "\\\\\\\\\\\\",
            "test\\",
            "file'\\",
            'file"\\',
            "'\\",
            '"\\',
            "\\'" * 10,
            '\\"' * 10,
            "'" * 11,  # Unbalanced odd quotes
            '"' * 11,

            # HTTP/Protocol confusion
            "GET / HTTP/1.0\r\n",
            "HTTP/1.1 200 OK\r\n",

            # CVE-2024-46483: Xlight FTP heap overflow (long strings + \xff)
            "\xff\xff\xff\xff",
            "\x00\x00\x00\x00",
            "\xff" * 50,
            "A" * 1500 + "\xff\xff\xff",
            "B" * 2048,
            "C" * 5000,

            # FTP specific
            "anonymous",
            "ftp",
            "admin",
            "root",
        ]
        return mutations

    @staticmethod
    def path_mutators() -> List[str]:
        """Path-specific mutations including CVE patterns."""
        return [
            "/",
            "//",
            "/./",
            "/../",
            "/..." ,
            "/.../",
            "../",
            "..\\",
            # CVE-2019-18217: Long path traversal for CWD crash
            "../" * 50,
            "../../../etc/passwd",
            "/../../../../../../../etc/passwd",
            "../../../etc/shadow",
            # Sensitive file paths
            "/tmp",
            "/etc",
            "/etc/passwd",
            "/etc/shadow",
            "/root",
            "/home",
            "/var",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/sys/class/net",
            "/.ssh/id_rsa",
            "/dev/null",
            # Windows paths
            "C:\\",
            "C:\\Windows",
            "C:\\Windows\\System32",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "\\\\server\\share",
            "NUL",
            "CON",
            "PRN",
            "AUX",
            "LPT1",
            "COM1",
            # Boundary cases
            "a" * 255,  # Max filename length
            "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z" * 10,
            # Null byte injection (CVE pattern)
            "/etc/passwd\x00.txt",
            "file.txt\x00.jpg",
            # CVE-2024-4040: Template injection in paths
            "..%2f",
            "../${env}",
            "../{{config}}",
            "${../../../etc/passwd}",
            "/home/../${user}",
            "sessions.obj",
            "users.xml",
            # CVE-2023-51713: Quote/backslash in paths
            "/tmp/file\\",
            "../test'\\",
            '/path"\\',
            "file'" * 5,
            # CVE-2024-46483: Long paths for heap overflow
            "/" + "A" * 1500,
            "../" * 100 + "file.txt",
            "subdir/" * 200,
        ]

    @staticmethod
    def port_mutators() -> List[str]:
        """PORT command specific mutations."""
        return [
            "127,0,0,1,0,21",
            "127,0,0,1,255,255",
            "0,0,0,0,0,0",
            "255,255,255,255,255,255",
            "192,168,1,1,0,22",
            "-1,0,0,0,0,0",
            "256,0,0,0,0,0",
            "127,0,0,1," + ",".join(["A"] * 100),
            "A" * 100,
        ]

    @staticmethod
    def site_mutators() -> List[str]:
        """SITE command specific mutations including CVE patterns."""
        return [
            "HELP",
            "CHMOD 777 file",
            "EXEC cmd",
            "EXEC /bin/sh",
            # CVE-2019-12815: mod_copy arbitrary file copy
            "CPFR /etc/passwd",
            "CPTO /tmp/passwd",
            "CPFR /etc/shadow",
            "CPTO ../../../tmp/evil",
            # CVE-2015-3306: mod_copy file read (sensitive paths)
            "CPFR /proc/self/cmdline",
            "CPFR /proc/self/environ",
            "CPFR /sys/class/net",
            "CPFR /.ssh/id_rsa",
            "CPFR /.gnupg/secring.gpg",
            "CPFR /dev/mem",
            # Buffer overflow attempts
            "CPFR /" + "A" * 1000,
            "CPTO /" + "B" * 1000,
            "UTIME file 20230101120000",
            "SYMLINK source dest",
            "CHMOD " + "7" * 100 + " file",
            # CVE-2024-48651: SQL injection for privilege escalation
            "CPFR /etc/passwd' OR '1'='1",
            "CPTO /tmp/test'; --",
            "CHMOD 777 file' UNION SELECT",
            "CPFR admin'--",
            "CPFR root'--",
            "CPFR ' OR ''='",
            # CVE-2024-4040: Template injection in SITE commands
            "CPFR ${/etc/passwd}",
            "CPTO {{config}}",
            "CPFR <INCLUDE>",
            "CPFR sessions.obj",
            "CPFR users.xml",
            # CVE-2023-51713: Quote/backslash patterns
            "CPFR /tmp\\",
            "CPTO file'\\",
            'CPFR path"\\',
            "CHMOD 777 file\\",
            # CVE-2024-46483: Long SITE commands for heap overflow
            "CPFR /" + "A" * 2000,
            "CPTO /" + "B" * 2000 + "\xff\xff",
        ]

    @staticmethod
    def apply_random_mutation(base: str) -> str:
        """Apply a random mutation to the base string."""
        mutations = [
            lambda s: s + "A" * random.randint(100, 1000),
            lambda s: s.replace("a", "%00"),
            lambda s: s + "\x00" * random.randint(1, 100),
            lambda s: s + "../" * random.randint(1, 20),
            lambda s: s + "%n" * random.randint(1, 20),
            lambda s: "".join(random.choice(string.printable) for _ in range(len(s) * 2)),
            lambda s: s[:len(s)//2] + "\xff" * 100 + s[len(s)//2:],
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s + "; " + s,
            # CVE-2024-46483: Long string for heap overflow
            lambda s: s + "B" * random.randint(1500, 3000),
            lambda s: "\xff" * random.randint(20, 100) + s,
            # CVE-2024-4040: Template injection
            lambda s: "${" + s + "}",
            lambda s: "{{" + s + "}}",
            lambda s: s + "${env}",
            # CVE-2024-48651: SQL injection
            lambda s: s + "' OR '1'='1",
            lambda s: s + "'; --",
            lambda s: s + "' UNION SELECT",
            # CVE-2023-51713: Quote/backslash
            lambda s: s + "\\",
            lambda s: s + "'\\",
            lambda s: s + "'" * random.randint(5, 15),
        ]

        mutation = random.choice(mutations)
        try:
            return mutation(base)
        except:
            return base


class BaselineBoofuzzFuzzer(BaseFuzzer):
    """
    Baseline fuzzer using pure boofuzz-style mutations.
    This is the control group for the ablation study.
    """

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector = None,
    ):
        super().__init__(
            fuzzer_type=FuzzerType.BASELINE,
            config=config,
            metrics_collector=metrics_collector,
        )

        self._mutators = BoofuzzMutators()
        self._seed_pool: List[FTPCommand] = []

    def generate_seeds(self) -> List[FTPCommand]:
        """Generate seed inputs using boofuzz-style patterns."""
        seeds = []

        # Generate seeds for each FTP command type
        command_templates = {
            # CVE-2024-48651: SQL injection in USER/PASS for privilege escalation
            "USER": ["anonymous", "ftp", "admin", "root", "test",
                     "admin'--", "root'--", "' OR '1'='1", "admin' UNION SELECT"],
            "PASS": ["anonymous@", "ftp@ftp.com", "", "password", "admin",
                     "' OR '1'='1", "'; --", "password' UNION SELECT"],
            # CVE-2023-51713: Quote/backslash for OOB read
            "CWD": ["/", "/tmp", ".", "..", "~", "/tmp\\", "../'\\", 'path"\\'],
            "MKD": ["testdir", "new_folder", "a", "test123", "dir\\", "new'\\"],
            "RMD": ["testdir", "old_folder", "dir\\"],
            "DELE": ["file.txt", "test.dat", "file\\", "test'\\"],
            # CVE-2024-4040: Template injection in file paths
            "RETR": ["welcome.txt", "readme.txt", "data/sample.dat",
                     "${config}", "{{file}}", "sessions.obj", "users.xml"],
            "STOR": ["upload.txt", "newfile.dat", "${file}", "{{upload}}"],
            # CVE-2019-12815: mod_copy
            "SITE": ["HELP", "CHMOD 777 file", "CPFR /tmp/test",
                     "CPFR /etc/passwd", "CPFR ${config}", "CPFR sessions.obj"],
            "PORT": ["127,0,0,1,0,21"],
            "PASV": [""],
            "LIST": ["", "/", ".", "${dir}", "{{path}}"],
            "NLST": ["", "/", "."],
            "PWD": [""],
            "SYST": [""],
            "FEAT": [""],
            "QUIT": [""],
            # CVE-2022-34977: Buffer overflow in MLSD
            "MLSD": ["", "/", ".", "A" * 600, "B" * 2500],
        }

        for cmd, args_list in command_templates.items():
            for args in args_list:
                seeds.append(FTPCommand(name=cmd, args=args))

        # Add mutated versions
        string_mutations = self._mutators.string_mutators()
        for cmd in ["USER", "PASS", "CWD", "MKD", "SITE", "RETR", "STOR"]:
            for mutation in random.sample(string_mutations, min(20, len(string_mutations))):
                seeds.append(FTPCommand(name=cmd, args=mutation))

        # Add path mutations
        path_mutations = self._mutators.path_mutators()
        for cmd in ["CWD", "RETR", "STOR", "DELE", "RMD", "MKD"]:
            for mutation in random.sample(path_mutations, min(10, len(path_mutations))):
                seeds.append(FTPCommand(name=cmd, args=mutation))

        # Add SITE mutations
        site_mutations = self._mutators.site_mutators()
        for mutation in site_mutations:
            seeds.append(FTPCommand(name="SITE", args=mutation))

        # Add PORT mutations
        port_mutations = self._mutators.port_mutators()
        for mutation in port_mutations:
            seeds.append(FTPCommand(name="PORT", args=mutation))

        self._seed_pool = seeds
        self.logger.log_seed_generation(len(seeds), "boofuzz")

        # Record metrics
        self.metrics.record_seed_generation(
            self.fuzzer_type.value,
            self.session_id,
            len(seeds),
            from_llm=False
        )

        return seeds

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Mutate a seed using boofuzz-style mutations."""
        # Choose mutation strategy
        strategies = ["string", "path", "random", "combine"]
        strategy = random.choice(strategies)

        mutated_args = seed.args

        if strategy == "string":
            mutations = self._mutators.string_mutators()
            mutated_args = random.choice(mutations)

        elif strategy == "path":
            if seed.name in ["CWD", "RETR", "STOR", "DELE", "RMD", "MKD"]:
                mutations = self._mutators.path_mutators()
                mutated_args = random.choice(mutations)

        elif strategy == "random":
            mutated_args = self._mutators.apply_random_mutation(seed.args)

        elif strategy == "combine":
            # Combine original with mutation
            mutations = self._mutators.string_mutators()
            mutation = random.choice(mutations)
            mutated_args = seed.args + mutation

        # Record mutation
        self.metrics.record_mutation(
            self.fuzzer_type.value,
            self.session_id,
            strategy,
            from_llm=False
        )

        return FTPCommand(name=seed.name, args=mutated_args)

    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run the baseline fuzzer."""
        import hashlib
        iterations = iterations or self.config.max_iterations

        # Start metrics session
        self.metrics.start_session(self.fuzzer_type.value, self.session_id)

        # Generate initial seeds
        if not self._seed_pool:
            self.generate_seeds()

        # Connect to server
        if not self.connect():
            logging.error("Failed to connect to FTP server")
            return []

        # Authenticate
        if not self.authenticate():
            logging.error("Failed to authenticate")
            return []

        logging.info(f"Starting baseline boofuzz fuzzer for {iterations} iterations")

        results = []

        for i in range(iterations):
            self._current_iteration = i

            # Select seed
            seed = random.choice(self._seed_pool)

            # Decide whether to mutate
            if random.random() < 0.7:  # 70% chance to mutate
                command = self.mutate(seed)
            else:
                command = seed

            # Send command and get result
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            # Generate payload hash for unique tracking
            payload_hash = hashlib.md5(command.to_bytes()).hexdigest()[:16]
            crash_hash = f"{result.command.name}_{payload_hash}"

            # Record iteration with detailed coverage info
            self.metrics.record_iteration(
                self.fuzzer_type.value,
                self.session_id,
                result.success,
                result.response_time_ms,
                method=command.name,
                path=command.args[:100] if command.args else None,
                status_code=result.response_code
            )

            # Handle errors and crashes
            if not result.success:
                if "Timeout" in result.error_message:
                    self.metrics.record_error(
                        self.fuzzer_type.value,
                        self.session_id,
                        error_type="timeout"
                    )
                elif "Connection" in result.error_message or result.crashed:
                    self.metrics.record_error(
                        self.fuzzer_type.value,
                        self.session_id,
                        error_type="connection"
                    )
                else:
                    self.metrics.record_error(
                        self.fuzzer_type.value,
                        self.session_id,
                        error_type="general"
                    )

            # Record crashes and CVE triggers
            if result.crashed or result.cve_triggered:
                self.metrics.record_crash(
                    self.fuzzer_type.value,
                    self.session_id,
                    crash_hash=crash_hash,
                    cve_id=result.cve_triggered,
                    payload_hash=payload_hash
                )
                self._handle_crash(result)

            # Log progress periodically
            if (i + 1) % 100 == 0:
                logging.info(f"Progress: {i + 1}/{iterations} iterations")

        self.disconnect()
        logging.info(f"Completed {iterations} iterations")
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_statistics()
        stats["seed_pool_size"] = len(self._seed_pool)
        stats["mutation_types"] = ["string", "path", "random", "combine"]
        return stats
