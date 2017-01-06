
#include "state.h"

#include <memory>
#include <sstream>

using namespace std;

map<unsigned int, shared_ptr<Symbolic>> State::_initial_values = [] {
    map<unsigned int, shared_ptr<Symbolic>> result;

    for(const auto &r : AMD64_REGISTERS) {
        const auto &initial = make_shared<Symbolic>(format_initial_value(r));
        result[r] = initial;
    }

    return result;
}();

/*!
 * \brief Constructs a new `State` and initializes it (unless specified
 * otherwise).
 *
 * \param initialize `True` per default. Whether the state should be fully
 * initialized. \see `set_initial_state`
 *
 * \todo This is specific to x86_64. Possibly better to provide a generic
 * base class first.
 */
State::State(bool initialize)
    : _unknown(make_shared<Unknown>()) {
    if(initialize) {
        set_initial_state();
    }
}

/*!
 * \brief Prints the state to the given output stream.
 * \param stream The output stream to which the state is printed.
 * \param state The `State` itself.
 * \return The (modified) output stream `stream`.
 */
ostream &operator<<(ostream &stream, const State &state) {
    for(const auto &kv : state._state) {
        stream << *kv.first << " -> " << *kv.second << endl;
    }

    return stream;
}

const string State::format_initial_value(size_t offset) {
    // TODO: Precompute this.
    const auto &needle = AMD64_DISPLAY_REGISTERS.find(offset);
    if(needle != AMD64_DISPLAY_REGISTERS.cend()) {
        return "init_" + needle->second;
    }

    stringstream stream;
    string symbolic_value;

    stream << "init_r" << dec << offset;
    stream >> symbolic_value;
    return symbolic_value;
}

/*!
 * \brief Formats a return value of a call at the given address.
 * \param address The address of the call whose return value shall be formatted.
 * \return A unique string to be used for a symbol describing the return value
 * of the call.
 */
const string State::format_return_value(uintptr_t address) {
    stringstream stream;
    stream << "return_" << hex << address;

    return stream.str();
}

/*!
 * \brief Initializes the state in respect to x86_64 registers.
 *
 * Each register gets assigned a symbol depicting its initial value.
 *
 * \see `State::format_initial_value`
 */
void State::set_initial_state() {
    for(const auto &r : AMD64_REGISTERS) {
        // Copy necessary here?
        const auto &dst = make_shared<Register>(r);
        const auto &src = make_shared<Symbolic>(format_initial_value(r));

        _state[dst] = src;
    }
}

/*!
 * \brief Removes all System V scratch registers from the state.
 *
 * \todo Support different calling conventions.
 * \see `system_v_scratch`
 */
void State::purge_scratch_registers(FileFormatType file_format) {
    switch(file_format) {
        case FileFormatELF64:
            for(const auto &scratch : system_v_scratch) {
                _state.erase(scratch);
            }
            break;
        case FileFormatPE64:
            for(const auto &scratch : msvc_scratch) {
                _state.erase(scratch);
            }
            break;
        default:
            throw runtime_error("Do not know how to "\
                                "handle file format.");
    }
}

/*!
 * \brief Merge another `State` into this one.
 *
 * Already existing entries are overwritten with the values of the other state.
 *
 * \param other The state that is merged into this.
 */
void State::merge(const State &other) {
    for(const auto &kv : other._state) {
        _state[kv.first] = kv.second;
    }
}

/*!
 * \brief Helper function to return all memory indirections recorded in the
 * state.
 *
 * The first entry of the pair denotes the memory address, whereas the second
 * entry denotes the value that is to be written.
 *
 * \return A vector of key/value pairs describing a memory access.
 */
const Expressions State::get_memory_accesses() const {
    Expressions result;
    for(const auto &kv : _state) {
        if(kv.first->type() == ExpressionIndirection) {
            result.push_back(kv);
        }
    }

    return result;
}

/*!
 * \brief Helper function to optimize the representation of the state.
 * \param do_purge_unchanged `true`, if unchanged registers (those still set to
 * their initial value) shall be removed from state.
 *
 * \todo Purging unchanged registers may lead to issues regarding the binding
 * of `rsp`. It is assumed to be set in some cases. We should rather check for
 * existence and throw `runtime_error` on mismatch.
 */
void State::optimize(bool do_purge_unchanged) {
    // Transitively kill expressions affected by a self-reference.
    for(const auto &kv: _state) {
        if(kv.second->contains(*kv.first)) {
            kill(kv.first, kv.second);
        }
    }

    /* Purging unchanged registers will fail when propagating states (e.g.,
     * an AbiHint requires rsp to be defined and cannot implement calling
     * conventions properly if it has been purged. Disabled by default.
     */
    if(optimizer() && do_purge_unchanged) {
        purge_unchanged();
    }
}

bool State::optimizer(bool do_purge_unchanged) {
    bool dirty = false;
    if(do_purge_unchanged) {
        dirty |= purge_unchanged();
    }

    dirty |= purge_uninteresting();

    optimize_entries();
    dirty |= propagate();

    return dirty;
}

bool State::propagate() {
    bool dirty = false;

    // Propagate any values which are also keys in the same state.
    for(const auto &kv : _state) {
        const auto &value = kv.second;

        const auto &needle = _state.find(value);
        if(needle != _state.cend()) {
            _state[kv.first] = needle->second;
            dirty = true;
        }
    }

    // Propagate sub-expressions.
    for(const auto &kv : _state) {
        for(const auto &p : _state) {
            dirty |= p.first->propagate(kv.first, kv.second);
            dirty |= p.second->propagate(kv.first, kv.second);
        }
    }

    return dirty;
}

void State::optimize_entries() {
    for(auto i = _state.begin(); i != _state.end(); ++i) {
        i->first->optimize();
        i->second->optimize();
    }
}

/* Set explicitly to Unknown instead of deleting and keep Unknown:s? As not to
 * mess up logic trying to get a value regardless. Need to think about this.
 */
bool State::purge_uninteresting() {
    bool dirty = false;

    for(auto i = _state.begin(); i != _state.end();) {
        Expression &key = *i->first;
        Expression &value = *i->second;

        if(key.type() == ExpressionTemporary) {
            i = _state.erase(i);
            dirty = true;
            continue;
        }

        // We want to keep Unknown:s for register values only.
        if(value.type() == ExpressionUnknown &&
           key.type() != ExpressionRegister) {
            i = _state.erase(i);
            dirty = true;
            continue;
        }

        if(key.type() == ExpressionRegister) {
            auto reg = static_cast<const Register&>(key);
            if(reg.offset() > OFFB_R15 && reg.offset() != OFFB_RIP) {

                i = _state.erase(i);
                dirty = true;
                continue;
            }
        }

        ++i;
    }

    return dirty;
}

bool State::purge_unchanged() {
    bool dirty = false;

    for(auto i = _state.begin(); i != _state.end();) {
        Expression &key = *i->first;
        Expression &value = *i->second;

        if(key.type() == ExpressionRegister) {
            auto offset = static_cast<const Register&>(key).offset();
            const auto &initial = _initial_values.find(offset);

            if(initial != _initial_values.cend()) {
                if(*initial->second == value) {
                    i = _state.erase(i);
                    dirty = true;
                    continue;
                }
            }
        }

        ++i;
    }

    return dirty;
}

InternalState::iterator State::erase(const InternalState::iterator &iterator) {
    return _state.erase(iterator);
}

size_t State::erase(const InternalState::key_type &key) {
    return _state.erase(key);
}

bool State::find(const InternalState::key_type &key,
                 arg_out InternalState::iterator &iterator) {
    InternalState::iterator needle = _state.find(key);
    if(needle == _state.end()) {
        return false;
    }

    iterator = needle;
    return true;
}

bool State::find(const InternalState::key_type &key,
                 arg_out InternalState::const_iterator &iterator) const {
    InternalState::const_iterator needle = _state.find(key);
    if(needle == _state.cend()) {
        return false;
    }

    iterator = needle;
    return true;
}

kill_results State::kill_helper(const ExpressionPtr &key,
                                const ExpressionPtr &value) {
    kill_results affected;

    for(auto i = _state.begin(), e = _state.end(); i != e; ++i) {
        if(i->second->contains(*key) || i->second->contains(*value)) {
            if(i->second->type() != ExpressionUnknown) {
                affected.insert(i->first);
                i->second = _unknown;
            }
        }
    }

    return affected;
}

void State::kill(const ExpressionPtr &key, const ExpressionPtr &value) {
    _state[key] = _unknown;

    kill_results affected = { key };
    while(!affected.empty()) {
        kill_results work_list;

        for(const auto &a : affected) {
            const auto &killed = kill_helper(a, value);

            for(const auto &k : killed) {
                work_list.insert(k);
            }
        }

        affected = work_list;
    }
}

void State::update(const InternalState::key_type &key,
                   const InternalState::mapped_type &value) {
    _state[key] = value;
}
