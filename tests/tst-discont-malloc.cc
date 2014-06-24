/*
 * Copyright (C) 2014 Paweł Dziepak
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <algorithm>
#include <iostream>
#include <cassert>
#include <cstdlib>
#include <stdio.h>
#include <unistd.h>

#include <boost/intrusive/set.hpp>

namespace bi = boost::intrusive;

struct alloc : public bi::set_base_hook<> {
    friend bool operator<(const alloc& a, const alloc& b) {
        return &a < &b;
    }
};

bi::set<alloc> allocs;

constexpr unsigned step = 4096;
constexpr unsigned avoid_oom = 4096 * 16;
constexpr unsigned discont_alloc = avoid_oom * 4096 * 2;

int main()
{
    std::cerr << "Running discontinuous malloc tests\n";
    while (sysconf(_SC_AVPHYS_PAGES) > avoid_oom) {
        auto v = malloc(step);
        assert(v);
        auto& p = *new (v) alloc;
        assert(allocs.count(p) == 0);
        allocs.insert(p);
    }
    unsigned freed = 0;
    for (auto& p : allocs) {
        auto nx = std::next(allocs.iterator_to(p));
        auto a1 = static_cast<void*>(&p);
        auto a2 = static_cast<void*>(&*nx);
        if (a1 + discont_alloc > a2) {
            allocs.erase(nx);
            free(a2);
            freed += step;
            if (freed >= discont_alloc) {
                break;
            }
        }
    }
    assert(freed >= discont_alloc);
    auto p = malloc(discont_alloc);
    assert(p);
    std::cerr << "discontinuous malloc tests succeeded\n";
}
