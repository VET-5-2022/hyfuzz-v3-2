"""
State Machine for FTP Protocol.
Models the stateful nature of FTP for intelligent fuzzing.
"""
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import random


class FTPState(Enum):
    """FTP protocol states."""
    DISCONNECTED = auto()
    CONNECTED = auto()           # After TCP connection, received banner
    USER_SENT = auto()           # After USER command
    AUTHENTICATED = auto()       # After successful PASS
    PASSIVE_MODE = auto()        # After PASV command
    ACTIVE_MODE = auto()         # After PORT command
    TRANSFER_READY = auto()      # Ready for data transfer
    RENAMING = auto()            # After RNFR, waiting for RNTO
    TRANSFER_IN_PROGRESS = auto()


@dataclass
class StateTransition:
    """Defines a valid state transition."""
    command: str
    from_states: Set[FTPState]
    to_state_success: FTPState
    to_state_failure: FTPState
    requires_args: bool = True
    success_codes: Set[int] = field(default_factory=lambda: {200, 220, 226, 227, 230, 250, 257, 331, 350})


class FTPStateMachine:
    """
    FTP Protocol State Machine.
    Models valid state transitions for stateful fuzzing.
    """

    def __init__(self):
        self.current_state = FTPState.DISCONNECTED
        self.state_history: List[Tuple[FTPState, str]] = []
        self._setup_transitions()

    def _setup_transitions(self):
        """Define all valid FTP state transitions."""
        self.transitions: Dict[str, StateTransition] = {
            # Connection commands
            "USER": StateTransition(
                command="USER",
                from_states={FTPState.CONNECTED, FTPState.AUTHENTICATED},
                to_state_success=FTPState.USER_SENT,
                to_state_failure=FTPState.CONNECTED,
                success_codes={331, 230}
            ),
            "PASS": StateTransition(
                command="PASS",
                from_states={FTPState.USER_SENT},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.CONNECTED,
                success_codes={230, 202}
            ),
            "ACCT": StateTransition(
                command="ACCT",
                from_states={FTPState.USER_SENT, FTPState.AUTHENTICATED},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.USER_SENT,
                success_codes={230, 202}
            ),

            # Transfer mode commands
            "PASV": StateTransition(
                command="PASV",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.PASSIVE_MODE,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={227}
            ),
            "EPSV": StateTransition(
                command="EPSV",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.PASSIVE_MODE,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={229}
            ),
            "PORT": StateTransition(
                command="PORT",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.ACTIVE_MODE,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={200}
            ),

            # Directory commands (require authentication)
            "CWD": StateTransition(
                command="CWD",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={250}
            ),
            "CDUP": StateTransition(
                command="CDUP",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={250, 200}
            ),
            "PWD": StateTransition(
                command="PWD",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={257}
            ),
            "MKD": StateTransition(
                command="MKD",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={257}
            ),
            "RMD": StateTransition(
                command="RMD",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={250}
            ),

            # File commands
            "DELE": StateTransition(
                command="DELE",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={250}
            ),

            # Rename commands (stateful sequence)
            "RNFR": StateTransition(
                command="RNFR",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.RENAMING,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={350}
            ),
            "RNTO": StateTransition(
                command="RNTO",
                from_states={FTPState.RENAMING},  # Only valid after RNFR
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={250}
            ),

            # Data transfer commands (require PASV/PORT first)
            "LIST": StateTransition(
                command="LIST",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={150, 125, 226}
            ),
            "NLST": StateTransition(
                command="NLST",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={150, 125, 226}
            ),
            "MLSD": StateTransition(
                command="MLSD",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={150, 125, 226}
            ),
            "RETR": StateTransition(
                command="RETR",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={150, 125, 226}
            ),
            "STOR": StateTransition(
                command="STOR",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={150, 125, 226}
            ),
            "APPE": StateTransition(
                command="APPE",
                from_states={FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={150, 125, 226}
            ),

            # Information commands (available in most states)
            "SYST": StateTransition(
                command="SYST",
                from_states={FTPState.CONNECTED, FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={215}
            ),
            "FEAT": StateTransition(
                command="FEAT",
                from_states={FTPState.CONNECTED, FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={211}
            ),
            "STAT": StateTransition(
                command="STAT",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={211, 212, 213}
            ),
            "HELP": StateTransition(
                command="HELP",
                from_states={FTPState.CONNECTED, FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={211, 214}
            ),
            "NOOP": StateTransition(
                command="NOOP",
                from_states={FTPState.CONNECTED, FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={200}
            ),

            # Type/Mode commands
            "TYPE": StateTransition(
                command="TYPE",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={200}
            ),
            "MODE": StateTransition(
                command="MODE",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={200}
            ),
            "STRU": StateTransition(
                command="STRU",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={200}
            ),

            # SITE commands
            "SITE": StateTransition(
                command="SITE",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                success_codes={200, 202, 214}
            ),

            # Session commands
            "QUIT": StateTransition(
                command="QUIT",
                from_states={FTPState.CONNECTED, FTPState.USER_SENT, FTPState.AUTHENTICATED,
                            FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE, FTPState.RENAMING},
                to_state_success=FTPState.DISCONNECTED,
                to_state_failure=FTPState.DISCONNECTED,
                requires_args=False,
                success_codes={221}
            ),
            "REIN": StateTransition(
                command="REIN",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE},
                to_state_success=FTPState.CONNECTED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={220}
            ),
            "ABOR": StateTransition(
                command="ABOR",
                from_states={FTPState.AUTHENTICATED, FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE,
                            FTPState.TRANSFER_IN_PROGRESS},
                to_state_success=FTPState.AUTHENTICATED,
                to_state_failure=FTPState.AUTHENTICATED,
                requires_args=False,
                success_codes={225, 226}
            ),
        }

    def get_valid_commands(self) -> List[str]:
        """Get commands valid in current state."""
        valid = []
        for cmd, transition in self.transitions.items():
            if self.current_state in transition.from_states:
                valid.append(cmd)
        return valid

    def can_execute(self, command: str) -> bool:
        """Check if command can be executed in current state."""
        if command not in self.transitions:
            return True  # Unknown commands allowed (for fuzzing)
        return self.current_state in self.transitions[command].from_states

    def execute(self, command: str, response_code: int) -> FTPState:
        """Execute command and update state based on response."""
        old_state = self.current_state

        if command in self.transitions:
            transition = self.transitions[command]
            if response_code in transition.success_codes:
                self.current_state = transition.to_state_success
            else:
                self.current_state = transition.to_state_failure

        self.state_history.append((old_state, command))
        return self.current_state

    def reset(self):
        """Reset to initial state."""
        self.current_state = FTPState.DISCONNECTED
        self.state_history = []

    def set_connected(self):
        """Set state to connected (after receiving banner)."""
        self.current_state = FTPState.CONNECTED

    def set_authenticated(self):
        """Set state to authenticated."""
        self.current_state = FTPState.AUTHENTICATED


@dataclass
class CommandSequence:
    """A sequence of FTP commands for stateful fuzzing."""
    commands: List[Tuple[str, str]]  # (command, args)
    description: str = ""
    target_state: Optional[FTPState] = None


class FTPSequenceGenerator:
    """
    Generates valid FTP command sequences for stateful fuzzing.
    """

    # Pre-defined attack sequences
    ATTACK_SEQUENCES = [
        # Authentication bypass attempts
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", ""),
            ],
            description="Anonymous login with empty password"
        ),
        CommandSequence(
            commands=[
                ("USER", "root"),
                ("PASS", "root"),
            ],
            description="Default credentials attempt"
        ),

        # Path traversal sequences
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
                ("CWD", "../../../etc"),
                ("LIST", ""),
            ],
            description="Path traversal via CWD"
        ),

        # SITE command exploitation
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
                ("SITE", "CPFR /etc/passwd"),
                ("SITE", "CPTO /tmp/pwned"),
            ],
            description="mod_copy exploitation"
        ),

        # Data transfer attacks
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
                ("PASV", ""),
                ("RETR", "../../../etc/passwd"),
            ],
            description="File read via path traversal"
        ),

        # Rename sequence (RNFR -> RNTO)
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
                ("RNFR", "/etc/passwd"),
                ("RNTO", "/tmp/passwd_copy"),
            ],
            description="Rename sensitive file"
        ),

        # Buffer overflow in authenticated state
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
                ("CWD", "A" * 5000),
            ],
            description="Buffer overflow in CWD"
        ),

        # Multiple PASV (resource exhaustion)
        CommandSequence(
            commands=[
                ("USER", "anonymous"),
                ("PASS", "anonymous@"),
            ] + [("PASV", "")] * 50,
            description="PASV flood"
        ),
    ]

    def __init__(self, state_machine: FTPStateMachine):
        self.state_machine = state_machine

    def generate_valid_sequence(self, length: int = 5) -> CommandSequence:
        """Generate a random valid command sequence."""
        commands = []

        # Always start with authentication
        commands.append(("USER", "anonymous"))
        commands.append(("PASS", "anonymous@"))

        # Simulate state transitions
        sim_state = FTPState.AUTHENTICATED

        for _ in range(length - 2):
            # Get valid commands for simulated state
            valid_cmds = []
            for cmd, transition in self.state_machine.transitions.items():
                if sim_state in transition.from_states:
                    valid_cmds.append((cmd, transition))

            if not valid_cmds:
                break

            # Choose random command
            cmd, transition = random.choice(valid_cmds)

            # Generate args
            args = self._generate_args_for_command(cmd)
            commands.append((cmd, args))

            # Update simulated state
            sim_state = transition.to_state_success

        return CommandSequence(commands=commands)

    def generate_invalid_sequence(self) -> CommandSequence:
        """Generate an intentionally invalid sequence (for negative testing)."""
        invalid_patterns = [
            # Commands before auth
            [("CWD", "/"), ("LIST", "")],
            # RNTO without RNFR
            [("USER", "anonymous"), ("PASS", "anonymous@"), ("RNTO", "newname")],
            # Data command without PASV/PORT
            [("USER", "anonymous"), ("PASS", "anonymous@"), ("LIST", "")],
            # Double USER
            [("USER", "user1"), ("USER", "user2"), ("PASS", "pass")],
        ]

        pattern = random.choice(invalid_patterns)
        return CommandSequence(
            commands=pattern,
            description="Invalid state sequence"
        )

    def generate_fuzz_sequence(self, base_sequence: CommandSequence, mutation_point: int) -> CommandSequence:
        """Generate a fuzzed version of a sequence, mutating at a specific point."""
        commands = list(base_sequence.commands)

        if mutation_point < len(commands):
            cmd, args = commands[mutation_point]
            # Apply mutation to args
            mutated_args = self._mutate_args(args)
            commands[mutation_point] = (cmd, mutated_args)

        return CommandSequence(
            commands=commands,
            description=f"Fuzzed at position {mutation_point}"
        )

    def _generate_args_for_command(self, command: str) -> str:
        """Generate appropriate arguments for a command."""
        args_map = {
            "USER": ["anonymous", "ftp", "admin", "test"],
            "PASS": ["anonymous@", "", "password", "test"],
            "CWD": ["/", "/tmp", "..", ".", "~"],
            "MKD": ["testdir", "newdir"],
            "RMD": ["testdir"],
            "DELE": ["test.txt"],
            "RETR": ["welcome.txt", "readme.txt"],
            "STOR": ["upload.txt"],
            "RNFR": ["oldname.txt"],
            "RNTO": ["newname.txt"],
            "TYPE": ["A", "I", "E", "L"],
            "MODE": ["S", "B", "C"],
            "STRU": ["F", "R", "P"],
            "PORT": ["127,0,0,1,4,1"],
            "SITE": ["HELP", "CHMOD 777 file"],
        }

        if command in args_map:
            return random.choice(args_map[command])
        return ""

    def _mutate_args(self, args: str) -> str:
        """Apply mutation to command arguments."""
        mutations = [
            lambda s: s + "A" * 1000,
            lambda s: "../" * 10 + s,
            lambda s: s + "\x00" * 10,
            lambda s: "%s%s%s%s" + s,
            lambda s: s.replace("/", "/../"),
        ]

        mutation = random.choice(mutations)
        return mutation(args)

    def get_attack_sequences(self) -> List[CommandSequence]:
        """Get pre-defined attack sequences."""
        return self.ATTACK_SEQUENCES.copy()
