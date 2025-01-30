class Fragment:
    # the offset of the fragment, in multiples of 8 octets
    offset: int
    # the size of the fragment, in multiples of 8 octets
    size: int
    # whether more fragments follow this one
    more: bool

    def __init__(self, offset: int, size: int, more: bool):
        self.offset = offset
        self.size = size
        self.more = more


class FragmentList:
    _fragments: list[Fragment]

    def __init__(self):
        self._fragments = []

    def add_fragment(self, fragment: Fragment):
        self._fragments.append(fragment)

    def check(self) -> str | None:
        # sort the fragments by offset
        self._fragments.sort(key=lambda frag: frag.offset)
        offset = 0
        more = True
        for fragment in self._fragments:
            if not more:
                # this is already the next packet, so there's something wrong
                return "Detected invalid fragmented packet without MF flag"
            if fragment.offset < offset:
                # this fragment overlaps the previous one
                return "Detected overlapping fragmented packet"
            offset += fragment.size
            # remember whether more fragments will follow this one
            more = fragment.more
        return None


# Keeps track of fragments to check whether there
# are any overlaps, which might be dangerous
class FragmentChecker:
    fragment_lists: dict[(str, str, int), FragmentList]

    def __init__(self):
        # we start with an empty fragment database
        self.fragment_lists = dict()

    def check(
        self,
        src: str,
        dst: str,
        frag_id: int,
        frag_size: int,
        frag_offset: int,
        more_frags: bool,
    ) -> str | None:
        # get existing fragments for this (src, dst, frag_id) combination
        key = (src, dst, frag_id)
        if key in self.fragment_lists:
            frag_list = self.fragment_lists[key]
        else:
            frag_list = FragmentList()
            self.fragment_lists[key] = frag_list
        # add this fragment to the list
        frag_list.add_fragment(Fragment(frag_offset, frag_size, more_frags))
        # check whether anything is wrong
        return frag_list.check()
