
#include "block.h"
#include "block_semantics.h"

/*!
 * \brief Constructs a `Block` object.
 * \param address Virtual address the block lies at.
 * \param block Pointer to an `IRSB` VEX block.
 * \param terminator Description of the block's terminator.
 */
Block::Block(uintptr_t address, IRSB *block, const Terminator &terminator)
    : _address(address), _vex_block(block), _terminator(terminator) {
}

/*!
 * \brief Retrieves the block's semantics using an instance of `BlockSemantics`.
 *
 * \todo For now, there is no easy way to sub-class how the semantics are
 * retrieved, this should change by allowing custom semantic extractors.
 *
 * \param[in,out] state Initial state as used when computing the semantics. This
 * is updated with the resulting state which reflects the block's semantics.
 */
void Block::retrieve_semantics(State &state) const {
    BlockSemantics semantics(*this, state);
    state = semantics.get_state();
}

/*!
 * \brief get_last_address
 * \return Returns the block's last virtual address
 * or 0 in case of an error.
 */
uint64_t Block::get_last_address() const {
    for(int i = _vex_block->stmts_used - 1; i >= 0; --i) {
        const auto &current = *_vex_block->stmts[i];
        if(current.tag == Ist_IMark) {
            const auto &temp = current.Ist.IMark;
            return temp.addr;
        }
    }

    return 0;
}
