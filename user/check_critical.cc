#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <vector>
#include <map>
#include <queue>
#include <algorithm>
#include <memory>

#include <unistd.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

#include "vma_protect.h"

void usage(const char* name) {
    fprintf(stderr,
"usage: %s exe\n"
"    checks for a simple version of vma_protect safety in exe\n"
"    caveats:\n"
"    - only considers .init, .fini, and .text* sections, and only this file\n"
"    - requires open and close syscalls to have syscall number and\n"
"      command hardcoded as constants\n"
"    - only supports syscall (not sysenter, int, etc.)\n"
"    - assumes only one protected region (disregards address argument)\n"
"    - proceeds conservatively, warning on indirect jumps which may be unexploitable in practice\n",
        name);
}

template <typename T>
struct cbuf_iter {
    typedef ssize_t                         difference_type;
    typedef T                               value_type;
    typedef T*                              pointer;
    typedef T&                              reference;
    typedef std::bidirectional_iterator_tag iterator_category;

    T* _buf;
    size_t _len;
    size_t _pos;

    /* Default constructor needed to satisfy ForwardIterator */
    cbuf_iter() = default;

    cbuf_iter(T* buf, size_t len) : _buf(buf), _len(len), _pos(0) {}

    inline bool operator==(const cbuf_iter &x) const {
        return _buf == x._buf && _len == x._len && _pos == x._pos;
    }
    inline bool operator!=(const cbuf_iter &x) const {
        return !(*this == x);
    }

    inline cbuf_iter& operator++() {
        ++_pos;
        if (_pos == _len) _pos = 0;
        return *this;
    }
    inline cbuf_iter operator++(int) {
        cbuf_iter ret = *this;
        ++(*this);
        return ret;
    }
    inline cbuf_iter& operator--() {
        if (_pos == 0) _pos = _len;
        --_pos;
        return *this;
    }
    inline cbuf_iter operator--(int) {
        cbuf_iter ret = *this;
        --(*this);
        return ret;
    }

    inline T& operator*() const {
        return _buf[_pos];
    }
};

/* Find sections to disassemble */

struct section {
    size_t index;
    const char* name;
    const uint8_t* data;
    size_t len;
};

typedef std::map<uint64_t, section> smap;

smap::iterator section_in(smap& m, uint64_t addr) {
    smap::iterator it = m.upper_bound(addr);
    if (it != m.begin()) {
        --it;
        if (addr < it->first + it->second.len) return it;
    }
    return m.end();
}

smap::iterator section_overlap(smap& m, uint64_t addr, size_t len) {
    smap::iterator it = m.lower_bound(addr);
    smap::iterator it2 = m.lower_bound(addr + len);
    if (it != it2) return it;
    return section_in(m, addr);
}

int gather_sections(Elf* e, smap& m) {
    size_t shstrind;
    if (elf_getshdrstrndx(e, &shstrind) < 0) {
        fprintf(stderr, "could not retrieve section header string table: %s\n", elf_errmsg(-1));
        return 2;
    }

    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(e, scn))) {
        Elf64_Shdr* shdr = elf64_getshdr(scn);
        if (!shdr) {
            fprintf(stderr, "could not retrieve section header: %s\n", elf_errmsg(-1));
            return 2;
        }
        char* name = elf_strptr(e, shstrind, shdr->sh_name);
        if (!name) {
            fprintf(stderr, "could not retrieve section name: %s\n", elf_errmsg(-1));
            return 2;
        }
        if (!strcmp(name, ".init") || !strcmp(name, ".fini")
                || !strcmp(name, ".plt") || !strncmp(name, ".text", 5)) {
            Elf_Data* data = elf_getdata(scn, NULL);
            if (!data) continue;
            uint64_t addr = shdr->sh_addr + data->d_off;
            size_t ind = elf_ndxscn(scn);
            smap::iterator it = section_overlap(m, addr, data->d_size);
            if (it != m.end()) {
                fprintf(stderr,
                        "sections overlap: %s (index %zu) maps [%#lx, %#lx), %s (index %zu) maps [%#lx, %#lx)\n",
                        name, ind, addr, addr + data->d_size, it->second.name,
                        it->second.index, it->first, it->first + it->second.len);
                return 2;
            }
            m.insert({addr, {ind, name, static_cast<uint8_t*>(data->d_buf), data->d_size}});
        }
    }

    return 0;
}

/* Make one pass, locating the starts and ends of critical regions */

typedef std::vector<uint64_t> addr_vec;

/*
 * For each syscall instruction, we just look backwards for the arguments; no
 * need to do that forever, though, so only maintain the last few instructions
 * seen. Initialize them to NOPs at the start of each section so the circular
 * buffer can be used as-is with no special case for the start of the section
 */

#define RING_SZ 16

int find_boundaries(csh handle, smap& m, addr_vec& starts, addr_vec& ends) {
    /* Somewhat stupidly, we have to allocate these all individually */
    cs_insn* ring[RING_SZ] = {nullptr};
    for (size_t i = 0; i < RING_SZ; ++i) {
        ring[i] = cs_malloc(handle);
        if (!ring[i]) {
            for (size_t j = 0; j < RING_SZ; ++j) {
                if (ring[j])
                    cs_free(ring[j], 1);
            }
            fprintf(stderr, "Out of memory!\n");
            return 2;
        }
    }

    for (const auto& p : m) {
        for (size_t i = 0; i < RING_SZ; ++i) {
            ring[i]->id = X86_INS_NOP;
        }
        cbuf_iter<cs_insn*> it(ring, RING_SZ);
        const uint8_t* code = p.second.data;
        size_t sz = p.second.len;
        uint64_t addr = p.first;

        while (cs_disasm_iter(handle, &code, &sz, &addr, *it)) {
            if ((*it)->id == X86_INS_SYSCALL) {
                uint64_t rax = -1;
                uint64_t rsi = -1;
                cbuf_iter<cs_insn*> bit = it;
                --bit;
                for (; bit != it; --bit) {
                    /* Break if we see a control flow instruction */
                    for (uint8_t k = 0; k < (*bit)->detail->groups_count; ++k) {
                        switch ((*bit)->detail->groups[k]) {
                            case X86_GRP_JUMP:
                            case X86_GRP_CALL:
                            case X86_GRP_RET:
                            case X86_GRP_INT:
                            case X86_GRP_IRET:
                                goto nested_break;
                            default:
                                break;
                        }
                    }
                    if ((*bit)->id == X86_INS_MOV) {
                        cs_x86& det = (*bit)->detail->x86;
                        cs_x86_op& op1 = det.operands[0];
                        cs_x86_op& op2 = det.operands[1];
                        if (det.op_count == 2 && op2.type == X86_OP_REG && op1.type == X86_OP_IMM) {
                            /*
                             * -1UL isn't a valid syscall number (nor command for SYS_vma_protect),
                             * so use it as in-band signaling that it hasn't yet been set (as we only
                             * want to take the last value)
                             */
                            if (rax == -1UL && (op2.reg == X86_REG_EAX || op2.reg == X86_REG_RAX))
                                rax = op1.imm;
                            else if (rsi == -1UL && (op2.reg == X86_REG_ESI || op2.reg == X86_REG_RSI))
                                rsi = op1.imm;
                        }
                    }
                }
nested_break: ;
                if (rax == SYS_vma_protect) {
                    if (rsi == VMA_OPEN)
                        starts.push_back((*it)->address);
                    else if (rsi == VMA_CLOSE)
                        ends.push_back((*it)->address);
                }
            }
            ++it;
        }
    }

    for (size_t i = 0; i < RING_SZ; ++i) {
        cs_free(ring[i], 1);
    }
    return 0;
}

/*
 * The main routine - trace instructions from open to close, ensuring no
 * unmatched returns or indirect jumps
 */

struct addr_state {
    uint64_t addr;
    int depth;
    std::shared_ptr<addr_state> prev;
};

typedef std::queue<std::pair<uint64_t, std::shared_ptr<addr_state>>> queue;

void enqueue(queue& q, uint64_t to, uint64_t from, int depth,
             std::shared_ptr<addr_state> cur) {
    std::shared_ptr<addr_state> next = std::make_shared<addr_state>();
    next->addr = from;
    next->depth = depth;
    next->prev = cur;
    q.push({to, next});
}

typedef std::map<uint64_t, size_t> vmap;

void vadd(vmap& m, uint64_t start, uint64_t end) {
    assert(end >= start);
    size_t len = end - start;
    if (!len) return;
    vmap::iterator above = m.lower_bound(start);
    assert(above == m.lower_bound(end));
    vmap::iterator below = above;
    if (below == m.begin()) {
        below = m.end();
    } else {
        --below;
        assert(start >= below->first + below->second);
    }
    vmap::iterator it = m.end();
    if (below != m.end() && start == below->first + below->second) {
        below->second += len;
        it = below;
    } else {
        auto p = m.insert({start, len});
        assert(p.second);
        it = p.first;
    }
    if (above != m.end() && end == above->first) {
        it->second += above->second;
        m.erase(above);
    }
}

void print_single(csh handle, cs_insn* i, smap& m, FILE* f, uint64_t addr) {
    smap::iterator it = section_in(m, addr);
    assert(it != m.end());
    const uint8_t* code = it->second.data + (addr - it->first);
    size_t sz = it->second.len - (addr - it->first);
    cs_disasm_iter(handle, &code, &sz, &addr, i);
    fprintf(f, "%#lx: %s %s\n", i->address, i->mnemonic, i->op_str);
}

void print_bt(csh handle, cs_insn* i, smap& m, FILE* f, std::shared_ptr<addr_state> as) {
    while (as) {
        print_single(handle, i, m, f, as->addr);
        as = as->prev;
    }
}

int insn_trace(csh handle, smap& m, addr_vec& ends, uint64_t start) {
    vmap visited;
    queue q;
    cs_insn* i = cs_malloc(handle);
    if (!i) {
        fprintf(stderr, "Out of memory!\n");
        return 2;
    }
    /* SYSCALL is 2 bytes long; skip it in analysis */
    enqueue(q, start + 2, start, 0, std::shared_ptr<addr_state>());
    printf("Tracing critical region starting at %#lx...\n", start);

    while (!q.empty()) {
        auto p = q.front();
        q.pop();
        vmap::iterator it2 = visited.upper_bound(p.first);
        if (it2 != visited.begin()) {
            --it2;
            if (p.first < it2->first + it2->second) continue;
            ++it2;
        }
        uint64_t end = it2 == visited.end() ? -1 : it2->first;
        if (p.first == end) continue;

        smap::iterator it = section_in(m, p.first);
        if (it == m.end()) {
            fprintf(stderr, "call/jump to %#lx not in disassembled section\n", p.first);
            return 3;
        }
        uint64_t addr = p.first;
        const uint8_t* code = it->second.data + (addr - it->first);
        size_t sz = it->second.len - (addr - it->first);

        while (cs_disasm_iter(handle, &code, &sz, &addr, i)) {
            /* First, check if it's the end of a region */
            if (i->id == X86_INS_SYSCALL && std::binary_search(ends.begin(), ends.end(), i->address))
                break;
            /*
             * Otherwise, only make one pass through the groups, pulling out the
             * areas of interest (why they didn't use bit flags for group
             * membership is beyond me, but there's a lot of questions with this
             * library, to be frank)
             */
            bool jmp = false;
            bool call = false;
            bool br_rela = false;
            bool ret = false;
            for (uint8_t j = 0; j < i->detail->groups_count; ++j) {
                switch (i->detail->groups[j]) {
                    case X86_GRP_JUMP:
                        jmp = true;
                        break;
                    case X86_GRP_CALL:
                        call = true;
                        break;
                    case X86_GRP_BRANCH_RELATIVE:
                        br_rela = true;
                        break;
                    case X86_GRP_RET:
                        ret = true;
                        break;
                    default:
                        break;
                }
            }
            if (jmp) {
                if (br_rela) {
                    enqueue(q, X86_REL_ADDR(*i), i->address, p.second->depth, p.second);
                    /* If it's unconditional, stop here */
                    if (i->id == X86_INS_JMP || i->id == X86_INS_LJMP) break;
                } else {
                    fprintf(stderr, "Warning: found indirect jump in critical region:\n");
                    fprintf(stderr, "%#lx: %s %s\n", i->address, i->mnemonic, i->op_str);
                    fprintf(stderr,
                            "This may not be a bug if you can ensure this code is never reached or\n"
                            "the register or memory location assuredly has a non-exploitable value\n");
                    fprintf(stderr, "Direct calls and jumps taken to arrive here:\n");
                    print_bt(handle, i, m, stderr, p.second);
                }
            } else if (call) {
                if (br_rela) {
                    enqueue(q, X86_REL_ADDR(*i), i->address, p.second->depth + 1, p.second);
                } else {
                    fprintf(stderr, "Warning: found indirect call in critical region:\n");
                    fprintf(stderr, "%#lx: %s %s\n", i->address, i->mnemonic, i->op_str);
                    fprintf(stderr,
                            "This may not be a bug if you can ensure this code is never reached or\n"
                            "the register or memory location assuredly has a non-exploitable value\n");
                    fprintf(stderr, "Direct calls and jumps taken to arrive here:\n");
                    print_bt(handle, i, m, stderr, p.second);
                }
            } else if (ret) {
                if (!p.second->depth) {
                    fprintf(stderr, "Warning: found unmatched ret in critical region:\n");
                    fprintf(stderr, "%#lx: %s\n", i->address, i->mnemonic);
                    fprintf(stderr,
                            "This is almost certainly a bug; attackers can easily manipulate the stack\n");
                    fprintf(stderr, "Direct calls and jumps taken to arrive here:\n");
                    print_bt(handle, i, m, stderr, p.second);
                }
                break;
            }
            /* Don't do extra work */
            if (addr == end) break;
        }
        vadd(visited, p.first, addr);
    }

    printf("Done tracing region\n");
    cs_free(i, 1);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    /* Open and parse ELF file */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "could not open %s: %m\n", argv[1]);
        return 2;
    }
    elf_version(EV_CURRENT);
    Elf* e = elf_begin(fd, ELF_C_READ_MMAP, NULL);
    if (!e) {
        fprintf(stderr, "could not parse %s: %s\n", argv[1], elf_errmsg(-1));
        return 2;
    }
    if (gelf_getclass(e) != ELFCLASS64) {
        fprintf(stderr, "%s: expected ELF64 file\n", argv[1]);
        return 2;
    }

    smap m;
    int r = gather_sections(e, m);
    if (r) return r;

    printf("Sections:\n");
    for (const auto& p : m) {
        printf("%s (index %zu): maps [%#lx, %#lx)\n", p.second.name, p.second.index,
               p.first, p.first + p.second.len);
    }

    csh handle;
    cs_err cr = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (cr != CS_ERR_OK) {
        fprintf(stderr, "could not initialize capstone context: %s\n", cs_strerror(cr));
        return 2;
    }
    cr = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (cr != CS_ERR_OK) {
        fprintf(stderr, "could not set capstone options: %s\n", cs_strerror(cr));
        return 2;
    }
    cr = cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    if (cr != CS_ERR_OK) {
        fprintf(stderr, "could not set capstone options: %s\n", cs_strerror(cr));
        return 2;
    }

    addr_vec starts, ends;
    r = find_boundaries(handle, m, starts, ends);
    if (r) return r;

    /*
     * These should be already sorted (if the sections are sorted by increasing
     * address); to be sure, sort them (to make searching faster later)
     */
    std::sort(starts.begin(), starts.end());
    std::sort(ends.begin(), ends.end());

    printf("Opens:\n");
    for (const auto& a : starts) {
        printf("%#lx\n", a);
    }

    printf("Closes:\n");
    for (const auto& a : ends) {
        printf("%#lx\n", a);
    }

    for (const auto& a : starts) {
        r = insn_trace(handle, m, ends, a);
        if (r) return r;
    }

    cr = cs_close(&handle);
    if (cr != CS_ERR_OK) {
        fprintf(stderr, "could not release capstone context: %s\n", cs_strerror(cr));
        return 2;
    }

    if (elf_end(e)) {
        fprintf(stderr, "could not release ELF resources: %s\n", elf_errmsg(-1));
        return 2;
    }

    if (close(fd)) {
        fprintf(stderr, "could not close %s: %m\n", argv[1]);
        return 2;
    }

    return 0;
}
