/* familycheck — DEEP NETWORK's /16 network-family calculator.
 *
 * The panel's edge blocklist works on whole /16 families (v3.21): blocking
 * one PoP removes its sibling addresses from every subscription row, the
 * scanner pool and the direct-egress pick. This tool is the standalone
 * reference implementation of that arithmetic — useful for checking which
 * family an edge belongs to and what a family covers, without the panel:
 *
 *     cc -O2 -o familycheck tools/c/familycheck.c && ./familycheck
 *     ./familycheck 143.244.45.177
 *     ./familycheck 143.244.45.177 143.244.45.200
 *     ./familycheck --range 143.244.0.0/16
 *     ./familycheck --contains 143.244.0.0/16 143.244.45.177
 *
 * Zero dependencies, C99, builds anywhere (Linux/macOS/WSL).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define OK 0
#define ERR_USAGE 1
#define ERR_PARSE 2

/* Parse dotted-quad into a host-order uint32. Returns 0 on success. */
static int parse_ip(const char *s, uint32_t *out)
{
    unsigned parts[4] = {0, 0, 0, 0};
    int idx = 0, digits = 0;
    const char *p = s;

    if (!s || !*s)
        return -1;
    for (; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            if (digits >= 3)
                return -1;
            parts[idx] = parts[idx] * 10 + (unsigned)(*p - '0');
            digits++;
            if (parts[idx] > 255)
                return -1;
        } else if (*p == '.') {
            if (digits == 0 || idx >= 3)
                return -1;
            idx++;
            digits = 0;
        } else {
            return -1;
        }
    }
    if (idx != 3 || digits == 0)
        return -1;
    *out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return 0;
}

/* The /16 family key — exactly what ipFamilyOf() computes in links.go. */
static uint32_t family_of(uint32_t ip)
{
    return ip >> 16;
}

static void format_ip(uint32_t ip, char *buf, size_t n)
{
    snprintf(buf, n, "%u.%u.%u.%u",
             (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

static int same_family(const char *a, const char *b, char *out, size_t n)
{
    uint32_t ia, ib;
    if (parse_ip(a, &ia) != 0 || parse_ip(b, &ib) != 0)
        return -1;
    if (family_of(ia) == family_of(ib))
        snprintf(out, n, "SAME family %u.%u.0.0/16",
                  (family_of(ia) >> 8) & 255, family_of(ia) & 255);
    else
        snprintf(out, n, "DIFFERENT families (%u.%u vs %u.%u)",
                  (family_of(ia) >> 8) & 255, family_of(ia) & 255,
                  (family_of(ib) >> 8) & 255, family_of(ib) & 255);
    return (int)(family_of(ia) == family_of(ib));
}

static void show_range(const char *cidr)
{
    char base[64];
    uint32_t ip, mask;
    int prefix = -1;
    char ip_part[64];

    if (sscanf(cidr, "%63[^/]/%d", ip_part, &prefix) != 2 || prefix < 0 || prefix > 32)
    {
        fprintf(stderr, "bad CIDR: %s\n", cidr);
        exit(ERR_PARSE);
    }
    if (parse_ip(ip_part, &ip) != 0)
    {
        fprintf(stderr, "bad IP in CIDR: %s\n", ip_part);
        exit(ERR_PARSE);
    }
    if (prefix > 16)
    {
        fprintf(stderr, "prefix /%d is narrower than /16; the blocklist "
                        "works on /16 families only\n", prefix);
        exit(ERR_USAGE);
    }
    mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;
    format_ip(network, base, sizeof base);
    printf("family range for %s:\n", cidr);
    printf("  network   %s\n", base);
    format_ip(broadcast, base, sizeof base);
    printf("  broadcast %s\n", base);
    printf("  hosts     %u\n", broadcast - network + 1);
    printf("  /16 key   %u.%u.0.0/16\n",
           (family_of(network) >> 8) & 255, family_of(network) & 255);
}

static void check_contains(const char *cidr, const char *candidate)
{
    uint32_t ip, net, mask;
    int prefix = -1;
    char ip_part[64], buf[32];

    if (sscanf(cidr, "%63[^/]/%d", ip_part, &prefix) != 2)
    {
        fprintf(stderr, "bad CIDR: %s\n", cidr);
        exit(ERR_PARSE);
    }
    if (parse_ip(ip_part, &net) != 0 || parse_ip(candidate, &ip) != 0)
    {
        fprintf(stderr, "bad address\n");
        exit(ERR_PARSE);
    }
    mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    int inside = (ip & mask) == (net & mask);
    format_ip(ip, buf, sizeof buf);
    printf("%s %s in %s\n", buf, inside ? "IS" : "IS NOT", cidr);
    exit(inside ? OK : ERR_USAGE);
}

static int selftest(void)
{
    uint32_t ip;
    int failures = 0;

    struct {
        const char *in;
        int want_err;
        uint32_t ip;
    } cases[] = {
        {"143.244.45.177", 0, (143u << 24) | (244u << 16) | (45u << 8) | 177u},
        {"0.0.0.0", 0, 0u},
        {"255.255.255.255", 0, 0xFFFFFFFFu},
        {"256.1.1.1", -1, 0},
        {"1.2.3", -1, 0},
        {"1.2.3.4.5", -1, 0},
        {"a.b.c.d", -1, 0},
        {"", -1, 0},
        {"1..3.4", -1, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int rc = parse_ip(cases[i].in, &ip);
        if ((rc != 0) != (cases[i].want_err != 0) ||
            (rc == 0 && ip != cases[i].ip)) {
            fprintf(stderr, "FAIL parse_ip(%s)\n", cases[i].in);
            failures++;
        }
    }

    /* family semantics: every address in 143.244.x.x shares one key */
    uint32_t a = (143u << 24) | (244u << 16);
    int all_same = 1;
    for (uint32_t low = 0; low < 65536; low += 4099) {
        if (family_of(a | low) != family_of(a)) {
            all_same = 0;
            break;
        }
    }
    if (!all_same) {
        fprintf(stderr, "FAIL family_of consistency\n");
        failures++;
    }

    printf("selftest: %zu parse cases + family walk — %s\n",
           sizeof cases / sizeof cases[0], failures ? "FAILED" : "all passed");
    return failures ? ERR_PARSE : OK;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: familycheck <ip>\n"
        "       familycheck <ip-a> <ip-b>        same /16 family?\n"
        "       familycheck --range <cidr/16>\n"
        "       familycheck --contains <cidr> <ip>\n"
        "       familycheck --test\n");
}

int main(int argc, char **argv)
{
    char buf[128];

    if (argc == 2 && strcmp(argv[1], "--test") == 0)
        return selftest();

    if (argc == 2 && strcmp(argv[1], "--range") == 0) {
        usage();
        return ERR_USAGE;
    }
    if (argc == 3 && strcmp(argv[1], "--range") == 0) {
        show_range(argv[2]);
        return OK;
    }
    if (argc == 4 && strcmp(argv[1], "--contains") == 0) {
        check_contains(argv[2], argv[3]);
    }

    if (argc == 2) {
        uint32_t ip;
        if (parse_ip(argv[1], &ip) != 0) {
            fprintf(stderr, "bad IP: %s\n", argv[1]);
            return ERR_PARSE;
        }
        printf("ip      %s\n", argv[1]);
        printf("/16 key %u.%u.0.0/16\n",
               (family_of(ip) >> 8) & 255, family_of(ip) & 255);
        return OK;
    }
    if (argc == 3) {
        int rc = same_family(argv[1], argv[2], buf, sizeof buf);
        if (rc < 0) {
            fprintf(stderr, "bad IP argument\n");
            return ERR_PARSE;
        }
        printf("%s vs %s: %s\n", argv[1], argv[2], buf);
        return rc ? OK : ERR_USAGE;
    }
    usage();
    return ERR_USAGE;
}
