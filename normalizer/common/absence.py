"""Conservative collection absence proofs, kept internal to normalization."""
from dataclasses import dataclass, field


@dataclass
class AbsenceResolver:
    confirmed_empty: set[str] = field(default_factory=set)

    def confirm(self, path, *, explicit=False, source_complete=False, domain_covered=False):
        """A complete source alone, or parser coverage alone, never proves absence."""
        if not explicit and not (source_complete and domain_covered):
            return False
        self.confirmed_empty.add('/' + path.strip('/'))
        return True

    def permits(self, path):
        return path in self.confirmed_empty
