/*Extended regular expression matching and search library.
  Copyright (C) Free Software Foundation, Inc.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.*/

static reg_errcode_t match_ctx_init (re_match_context_t *cache, int eflags,
				     Idx n);
static void match_ctx_clean (re_match_context_t *mctx);
static void match_ctx_free (re_match_context_t *cache);
static reg_errcode_t match_ctx_add_entry (re_match_context_t *cache, Idx node,
					  Idx str_idx, Idx from, Idx to);
static Idx search_cur_bkref_entry (const re_match_context_t *mctx, Idx str_idx);
static reg_errcode_t match_ctx_add_subtop (re_match_context_t *mctx, Idx node,
					   Idx str_idx);
static re_sub_match_last_t * match_ctx_add_sublast (re_sub_match_top_t *subtop,
						    Idx node, Idx str_idx);
static void sift_ctx_init (re_sift_context_t *sctx, re_dfastate_t **sifted_sts,
			   re_dfastate_t **limited_sts, Idx last_node,
			   Idx last_str_idx);
static reg_errcode_t re_search_internal (const regex_t *preg,
					 const char *string, Idx length,
					 Idx start, Idx last_start, Idx stop,
					 size_t nmatch, regmatch_t pmatch[],
					 int eflags);
static regoff_t re_search_2_stub (struct re_pattern_buffer *bufp,
				  const char *string1, Idx length1,
				  const char *string2, Idx length2,
				  Idx start, regoff_t range,
				  struct re_registers *regs,
				  Idx stop, bool ret_len);
static regoff_t re_search_stub (struct re_pattern_buffer *bufp,
				const char *string, Idx length, Idx start,
				regoff_t range, Idx stop,
				struct re_registers *regs,
				bool ret_len);
static unsigned int re_copy_regs (struct re_registers *regs, regmatch_t *pmatch,
				  Idx nregs, int regs_allocated);
static reg_errcode_t prune_impossible_nodes (re_match_context_t *mctx);
static Idx check_matching (re_match_context_t *mctx, bool fl_longest_match,
			   Idx *p_match_first);
static Idx check_halt_state_context (const re_match_context_t *mctx,
				     const re_dfastate_t *state, Idx idx);
static void update_regs (const re_dfa_t *dfa, regmatch_t *pmatch,
			 regmatch_t *prev_idx_match, Idx cur_node,
			 Idx cur_idx, Idx nmatch);
static reg_errcode_t push_fail_stack (struct re_fail_stack_t *fs,
				      Idx str_idx, Idx dest_node, Idx nregs,
				      regmatch_t *regs,
				      re_node_set *eps_via_nodes);
static reg_errcode_t set_regs (const regex_t *preg,
			       const re_match_context_t *mctx,
			       size_t nmatch, regmatch_t *pmatch,
			       bool fl_backtrack);
static reg_errcode_t free_fail_stack_return (struct re_fail_stack_t *fs);
static reg_errcode_t sift_states_backward (const re_match_context_t *mctx,
					   re_sift_context_t *sctx);
static reg_errcode_t build_sifted_states (const re_match_context_t *mctx,
					  re_sift_context_t *sctx, Idx str_idx,
					  re_node_set *cur_dest);
static reg_errcode_t update_cur_sifted_state (const re_match_context_t *mctx,
					      re_sift_context_t *sctx,
					      Idx str_idx,
					      re_node_set *dest_nodes);
static reg_errcode_t add_epsilon_src_nodes (const re_dfa_t *dfa,
					    re_node_set *dest_nodes,
					    const re_node_set *candidates);
static bool check_dst_limits (const re_match_context_t *mctx,
			      const re_node_set *limits,
			      Idx dst_node, Idx dst_idx, Idx src_node,
			      Idx src_idx);
static int check_dst_limits_calc_pos_1 (const re_match_context_t *mctx,
					int boundaries, Idx subexp_idx,
					Idx from_node, Idx bkref_idx);
static int check_dst_limits_calc_pos (const re_match_context_t *mctx,
				      Idx limit, Idx subexp_idx,
				      Idx node, Idx str_idx,
				      Idx bkref_idx);
static reg_errcode_t check_subexp_limits (const re_dfa_t *dfa,
					  re_node_set *dest_nodes,
					  const re_node_set *candidates,
					  re_node_set *limits,
					  struct re_backref_cache_entry *bkref_ents,
					  Idx str_idx);
static reg_errcode_t sift_states_bkref (const re_match_context_t *mctx,
					re_sift_context_t *sctx,
					Idx str_idx, const re_node_set *candidates);
static reg_errcode_t merge_state_array (const re_dfa_t *dfa,
					re_dfastate_t **dst,
					re_dfastate_t **src, Idx num);
static re_dfastate_t *find_recover_state (reg_errcode_t *err,
					 re_match_context_t *mctx);
static re_dfastate_t *transit_state (reg_errcode_t *err,
				     re_match_context_t *mctx,
				     re_dfastate_t *state);
static re_dfastate_t *merge_state_with_log (reg_errcode_t *err,
					    re_match_context_t *mctx,
					    re_dfastate_t *next_state);
static reg_errcode_t check_subexp_matching_top (re_match_context_t *mctx,
						re_node_set *cur_nodes,
						Idx str_idx);
static reg_errcode_t transit_state_bkref (re_match_context_t *mctx,
					  const re_node_set *nodes);
static reg_errcode_t get_subexp (re_match_context_t *mctx,
				 Idx bkref_node, Idx bkref_str_idx);
static reg_errcode_t get_subexp_sub (re_match_context_t *mctx,
				     const re_sub_match_top_t *sub_top,
				     re_sub_match_last_t *sub_last,
				     Idx bkref_node, Idx bkref_str);
static Idx find_subexp_node (const re_dfa_t *dfa, const re_node_set *nodes,
			     Idx subexp_idx, int type);
static reg_errcode_t check_arrival (re_match_context_t *mctx,
				    state_array_t *path, Idx top_node,
				    Idx top_str, Idx last_node, Idx last_str,
				    int type);
static reg_errcode_t check_arrival_add_next_nodes (re_match_context_t *mctx,
						   Idx str_idx,
						   re_node_set *cur_nodes,
						   re_node_set *next_nodes);
static reg_errcode_t check_arrival_expand_ecl (const re_dfa_t *dfa,
					       re_node_set *cur_nodes,
					       Idx ex_subexp, int type);
static reg_errcode_t check_arrival_expand_ecl_sub (const re_dfa_t *dfa,
						   re_node_set *dst_nodes,
						   Idx target, Idx ex_subexp,
						   int type);
static reg_errcode_t expand_bkref_cache (re_match_context_t *mctx,
					 re_node_set *cur_nodes, Idx cur_str,
					 Idx subexp_num, int type);
static bool build_trtable (const re_dfa_t *dfa,
			   re_dfastate_t *state);
static Idx group_nodes_into_DFAstates (const re_dfa_t *dfa,
				       const re_dfastate_t *state,
				       re_node_set *states_node,
				       bitset_t *states_ch);
static bool check_node_accept (const re_match_context_t *mctx,
			       const re_token_t *node, Idx idx);
static reg_errcode_t extend_buffers (re_match_context_t *mctx);

int
regexec (const regex_t * preg, const char * string, size_t nmatch,
		 regmatch_t pmatch[], int eflags)
{
  reg_errcode_t err;
  Idx start, length;

  if (eflags & ~(REG_NOTBOL | REG_NOTEOL | REG_STARTEND))
    return REG_BADPAT;

  if (eflags & REG_STARTEND)
    {
      start = pmatch[0].rm_so;
      length = pmatch[0].rm_eo;
    }
  else
    {
      start = 0;
      length = strlen (string);
    }

  __libc_lock_lock (dfa->lock);
  if (preg->no_sub)
    err = re_search_internal (preg, string, length, start, length,
			      length, 0, NULL, eflags);
  else
    err = re_search_internal (preg, string, length, start, length,
			      length, nmatch, pmatch, eflags);
  __libc_lock_unlock (dfa->lock);
  return err != REG_NOERROR;
}

regoff_t
re_match (struct re_pattern_buffer *bufp, const char *string, Idx length,
		  Idx start, struct re_registers *regs)
{
  return re_search_stub (bufp, string, length, start, 0, length, regs, true);
}

regoff_t
re_search (struct re_pattern_buffer *bufp, const char *string, Idx length,
		   Idx start, regoff_t range, struct re_registers *regs)
{
  return re_search_stub (bufp, string, length, start, range, length, regs,
			 false);
}

regoff_t
re_match_2 (struct re_pattern_buffer *bufp, const char *string1, Idx length1,
			const char *string2, Idx length2, Idx start,
			struct re_registers *regs, Idx stop)
{
  return re_search_2_stub (bufp, string1, length1, string2, length2,
			   start, 0, regs, stop, true);
}

regoff_t
re_search_2 (struct re_pattern_buffer *bufp, const char *string1, Idx length1,
			 const char *string2, Idx length2, Idx start, regoff_t range,
			 struct re_registers *regs, Idx stop)
{
  return re_search_2_stub (bufp, string1, length1, string2, length2,
			   start, range, regs, stop, false);
}

static regoff_t
re_search_2_stub (struct re_pattern_buffer *bufp,
		  const char *string1, Idx length1,
		  const char *string2, Idx length2,
		  Idx start, regoff_t range, struct re_registers *regs,
		  Idx stop, bool ret_len)
{
  const char *str;
  regoff_t rval;
  Idx len = length1 + length2;
  char *s = NULL;

  if (length1 < 0 || length2 < 0 || stop < 0 || len < length1)
    return -2;

  if (length2 > 0)
    if (length1 > 0)
      {
	s = re_malloc (char, len);

	if (s == NULL)
	  return -2;
	memcpy (s, string1, length1);
	memcpy (s + length1, string2, length2);
	str = s;
      }
    else
      str = string2;
  else
    str = string1;

  rval = re_search_stub (bufp, str, len, start, range, stop, regs,
			 ret_len);
  re_free (s);
  return rval;
}

static regoff_t
re_search_stub (struct re_pattern_buffer *bufp,
		const char *string, Idx length,
		Idx start, regoff_t range, Idx stop, struct re_registers *regs,
		bool ret_len)
{
  reg_errcode_t result;
  regmatch_t *pmatch;
  Idx nregs;
  regoff_t rval;
  int eflags = 0;
  Idx last_start = start + range;

  if (start < 0 || start > length)
    return -1;
  if (length < last_start || (0 <= range && last_start < start))
    last_start = length;
  else if (last_start < 0 || (range < 0 && start <= last_start))
    last_start = 0;

  __libc_lock_lock (dfa->lock);

  eflags |= (bufp->not_bol) ? REG_NOTBOL : 0;
  eflags |= (bufp->not_eol) ? REG_NOTEOL : 0;

  if (start < last_start && bufp->fastmap != NULL && !bufp->fastmap_accurate)
    re_compile_fastmap (bufp);

  if (bufp->no_sub)
    regs = NULL;

  if (regs == NULL)
    nregs = 1;
  else if (bufp->regs_allocated == REGS_FIXED
	       && regs->num_regs <= bufp->re_nsub)
    {
      nregs = regs->num_regs;
      if (nregs < 1)
	{
	  regs = NULL;
	  nregs = 1;
	}
    }
  else
    nregs = bufp->re_nsub + 1;
  pmatch = re_malloc (regmatch_t, nregs);
  if (pmatch == NULL)
    {
      rval = -2;
      goto out;
    }

  result = re_search_internal (bufp, string, length, start, last_start, stop,
			       nregs, pmatch, eflags);

  rval = 0;

  if (result != REG_NOERROR)
    rval = -1;
  else if (regs != NULL)
    {
      bufp->regs_allocated = re_copy_regs (regs, pmatch, nregs,
					   bufp->regs_allocated);
      if (bufp->regs_allocated == REGS_UNALLOCATED)
	rval = -2;
    }

  if (rval == 0)
    {
      if (ret_len)
	{
	  assert (pmatch[0].rm_so == start);
	  rval = pmatch[0].rm_eo - start;
	}
      else
	rval = pmatch[0].rm_so;
    }
  re_free (pmatch);
 out:
  __libc_lock_unlock (dfa->lock);
  return rval;
}

static unsigned int
re_copy_regs (struct re_registers *regs, regmatch_t *pmatch, Idx nregs,
	      int regs_allocated)
{
  int rval = REGS_REALLOCATE;
  Idx i;
  Idx need_regs = nregs + 1;

  if (regs_allocated == REGS_UNALLOCATED)
    {
      regs->start = re_malloc (regoff_t, need_regs);
      if (regs->start == NULL)
	return REGS_UNALLOCATED;
      regs->end = re_malloc (regoff_t, need_regs);
      if (regs->end == NULL)
	{
	  re_free (regs->start);
	  return REGS_UNALLOCATED;
	}
      regs->num_regs = need_regs;
    }
  else if (regs_allocated == REGS_REALLOCATE)
    {
      if (need_regs > regs->num_regs)
	{
	  regoff_t *new_start = re_realloc (regs->start, regoff_t, need_regs);
	  regoff_t *new_end;
	  if (new_start == NULL)
	    return REGS_UNALLOCATED;
	  new_end = re_realloc (regs->end, regoff_t, need_regs);
	  if (new_end == NULL)
	    {
	      re_free (new_start);
	      return REGS_UNALLOCATED;
	    }
	  regs->start = new_start;
	  regs->end = new_end;
	  regs->num_regs = need_regs;
	}
    }
  else
    {
      assert (regs_allocated == REGS_FIXED);
      assert (regs->num_regs >= nregs);
      rval = REGS_FIXED;
    }

  for (i = 0; i < nregs; ++i)
    {
      regs->start[i] = pmatch[i].rm_so;
      regs->end[i] = pmatch[i].rm_eo;
    }
  for ( ; i < regs->num_regs; ++i)
    regs->start[i] = regs->end[i] = -1;

  return rval;
}

void
re_set_registers (struct re_pattern_buffer *bufp, struct re_registers *regs,
			re_size_t num_regs, regoff_t *starts, regoff_t *ends)
{
  if (num_regs)
    {
      bufp->regs_allocated = REGS_REALLOCATE;
      regs->num_regs = num_regs;
      regs->start = starts;
      regs->end = ends;
    }
  else
    {
      bufp->regs_allocated = REGS_UNALLOCATED;
      regs->num_regs = 0;
      regs->start = regs->end = NULL;
    }
}

int
re_exec (const char *s)
{
  return 0 == regexec (&re_comp_buf, s, 0, NULL, 0);
}

static reg_errcode_t
re_search_internal (const regex_t *preg,
		    const char *string, Idx length,
		    Idx start, Idx last_start, Idx stop,
		    size_t nmatch, regmatch_t pmatch[],
		    int eflags)
{
  reg_errcode_t err;
  const re_dfa_t *dfa = (const re_dfa_t *) preg->buffer;
  Idx left_lim, right_lim;
  int incr;
  bool fl_longest_match;
  int match_kind;
  Idx match_first;
  Idx match_last = REG_MISSING;
  Idx extra_nmatch;
  bool sb;
  int ch;
  re_match_context_t mctx;
  char *fastmap = ((preg->fastmap != NULL && preg->fastmap_accurate
		    && start != last_start && !preg->can_be_null)
		   ? preg->fastmap : NULL);
  RE_TRANSLATE_TYPE t = preg->translate;

  memset (&mctx, '\0', sizeof (re_match_context_t));
  mctx.dfa = dfa;
  extra_nmatch = (nmatch > preg->re_nsub) ? nmatch - (preg->re_nsub + 1) : 0;
  nmatch -= extra_nmatch;

  if (preg->used == 0 || dfa->init_state == NULL
	  || dfa->init_state_word == NULL || dfa->init_state_nl == NULL
	  || dfa->init_state_begbuf == NULL)
    return REG_NOMATCH;

#ifdef DEBUG
  assert (0 <= last_start && last_start <= length);
#endif

  if (dfa->init_state->nodes.nelem == 0
      && dfa->init_state_word->nodes.nelem == 0
      && (dfa->init_state_nl->nodes.nelem == 0
	  || !preg->newline_anchor))
    {
      if (start != 0 && last_start != 0)
        return REG_NOMATCH;
      start = last_start = 0;
    }

  fl_longest_match = (nmatch != 0 || dfa->nbackref);

  err = re_string_allocate (&mctx.input, string, length, dfa->nodes_len + 1,
			    preg->translate, (preg->syntax & RE_ICASE) != 0,
			    dfa);
  if (err != REG_NOERROR)
    goto free_return;
  mctx.input.stop = stop;
  mctx.input.raw_stop = stop;
  mctx.input.newline_anchor = (unsigned char)preg->newline_anchor;

  err = match_ctx_init (&mctx, eflags, dfa->nbackref * 2);
  if (err != REG_NOERROR)
    goto free_return;

  if (nmatch > 1 || dfa->has_mb_node)
    {
      if (SIZE_MAX / sizeof (re_dfastate_t *) <= mctx.input.bufs_len)
	{
	  err = REG_ESPACE;
	  goto free_return;
	}

      mctx.state_log = re_malloc (re_dfastate_t *, mctx.input.bufs_len + 1);
      if (mctx.state_log == NULL)
	{
	  err = REG_ESPACE;
	  goto free_return;
	}
    }
  else
    mctx.state_log = NULL;

  match_first = start;
  mctx.input.tip_context = (eflags & REG_NOTBOL) ? CONTEXT_BEGBUF
			   : CONTEXT_NEWLINE | CONTEXT_BEGBUF;

  incr = (last_start < start) ? -1 : 1;
  left_lim = (last_start < start) ? last_start : start;
  right_lim = (last_start < start) ? start : last_start;
  sb = dfa->mb_cur_max == 1;
  match_kind =
    (fastmap
     ? ((sb || !(preg->syntax & RE_ICASE || t) ? 4 : 0)
	| (start <= last_start ? 2 : 0)
	| (t != NULL ? 1 : 0))
     : 8);

  for (;; match_first += incr)
    {
      err = REG_NOMATCH;
      if (match_first < left_lim || right_lim < match_first)
	goto free_return;

      switch (match_kind)
	{
	case 8:
	  break;

	case 7:
	  while ((match_first < right_lim)
		 && !fastmap[t[(unsigned char) string[match_first]]])
	    ++match_first;
	  goto forward_match_found_start_or_reached_end;

	case 6:
	  while ((match_first < right_lim)
		 && !fastmap[(unsigned char) string[match_first]])
	    ++match_first;

	forward_match_found_start_or_reached_end:
	  if (match_first == right_lim)
	    {
	      ch = match_first >= length
		       ? 0 : (unsigned char) string[match_first];
	      if (!fastmap[t ? t[ch] : ch])
		goto free_return;
	    }
	  break;

	case 4:
	case 5:
	  while (match_first >= left_lim)
	    {
	      ch = match_first >= length
		       ? 0 : (unsigned char) string[match_first];
	      if (fastmap[t ? t[ch] : ch])
		break;
	      --match_first;
	    }
	  if (match_first < left_lim)
	    goto free_return;
	  break;

	default:
	  for (;;)
	    {
	      re_size_t offset = match_first - mctx.input.raw_mbs_idx;
	      if (offset >= (re_size_t) mctx.input.valid_raw_len)
		{
		  err = re_string_reconstruct (&mctx.input, match_first,
					       eflags);
		  if (err != REG_NOERROR)
		    goto free_return;

		  offset = match_first - mctx.input.raw_mbs_idx;
		}
	      ch = (match_first >= length
		    ? 0 : re_string_byte_at (&mctx.input, offset));
	      if (fastmap[ch])
		break;
	      match_first += incr;
	      if (match_first < left_lim || match_first > right_lim)
	        {
	          err = REG_NOMATCH;
	          goto free_return;
	        }
	    }
	  break;
	}

      err = re_string_reconstruct (&mctx.input, match_first, eflags);
      if (err != REG_NOERROR)
	goto free_return;

      mctx.state_log_top = mctx.nbkref_ents = mctx.max_mb_elem_len = 0;
      match_last = check_matching (&mctx, fl_longest_match,
				   start <= last_start ? &match_first : NULL);
      if (match_last != REG_MISSING)
	{
	  if (match_last == REG_ERROR)
	    {
	      err = REG_ESPACE;
	      goto free_return;
	    }
	  else
	    {
	      mctx.match_last = match_last;
	      if ((!preg->no_sub && nmatch > 1) || dfa->nbackref)
		{
		  re_dfastate_t *pstate = mctx.state_log[match_last];
		  mctx.last_node = check_halt_state_context (&mctx, pstate,
							     match_last);
		}
	      if ((!preg->no_sub && nmatch > 1 && dfa->has_plural_match)
		  || dfa->nbackref)
		{
		  err = prune_impossible_nodes (&mctx);
		  if (err == REG_NOERROR)
		    break;
		  if (err != REG_NOMATCH)
		    goto free_return;
		  match_last = REG_MISSING;
		}
	      else
		break;
	    }
	}

      match_ctx_clean (&mctx);
    }

#ifdef DEBUG
  assert (match_last != REG_MISSING);
  assert (err == REG_NOERROR);
#endif

  if (nmatch > 0)
    {
      Idx reg_idx;

      for (reg_idx = 1; reg_idx < nmatch; ++reg_idx)
	pmatch[reg_idx].rm_so = pmatch[reg_idx].rm_eo = -1;

      pmatch[0].rm_so = 0;
      pmatch[0].rm_eo = mctx.match_last;

      if (!preg->no_sub && nmatch > 1)
	{
	  err = set_regs (preg, &mctx, nmatch, pmatch,
			  dfa->has_plural_match && dfa->nbackref > 0);
	  if (err != REG_NOERROR)
	    goto free_return;
	}

      for (reg_idx = 0; reg_idx < nmatch; ++reg_idx)
	if (pmatch[reg_idx].rm_so != -1)
	  {
	    assert (mctx.input.offsets_needed == 0);
	    pmatch[reg_idx].rm_so += match_first;
	    pmatch[reg_idx].rm_eo += match_first;
	  }
      for (reg_idx = 0; reg_idx < extra_nmatch; ++reg_idx)
	{
	  pmatch[nmatch + reg_idx].rm_so = -1;
	  pmatch[nmatch + reg_idx].rm_eo = -1;
	}

      if (dfa->subexp_map)
        for (reg_idx = 0; reg_idx + 1 < nmatch; reg_idx++)
          if (dfa->subexp_map[reg_idx] != reg_idx)
            {
              pmatch[reg_idx + 1].rm_so
                = pmatch[dfa->subexp_map[reg_idx] + 1].rm_so;
              pmatch[reg_idx + 1].rm_eo
                = pmatch[dfa->subexp_map[reg_idx] + 1].rm_eo;
            }
    }

 free_return:
  re_free (mctx.state_log);
  if (dfa->nbackref)
    match_ctx_free (&mctx);
  re_string_destruct (&mctx.input);
  return err;
}

static reg_errcode_t
prune_impossible_nodes (re_match_context_t *mctx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx halt_node, match_last;
  reg_errcode_t ret;
  re_dfastate_t **sifted_states;
  re_dfastate_t **lim_states = NULL;
  re_sift_context_t sctx;
#ifdef DEBUG
  assert (mctx->state_log != NULL);
#endif
  match_last = mctx->match_last;
  halt_node = mctx->last_node;

  if (SIZE_MAX / sizeof (re_dfastate_t *) <= match_last)
    return REG_ESPACE;

  sifted_states = re_malloc (re_dfastate_t *, match_last + 1);
  if (sifted_states == NULL)
    {
      ret = REG_ESPACE;
      goto free_return;
    }
  if (dfa->nbackref)
    {
      lim_states = re_malloc (re_dfastate_t *, match_last + 1);
      if (lim_states == NULL)
	{
	  ret = REG_ESPACE;
	  goto free_return;
	}
      while (1)
	{
	  memset (lim_states, '\0',
		  sizeof (re_dfastate_t *) * (match_last + 1));
	  sift_ctx_init (&sctx, sifted_states, lim_states, halt_node,
			 match_last);
	  ret = sift_states_backward (mctx, &sctx);
	  re_node_set_free (&sctx.limits);
	  if (ret != REG_NOERROR)
	      goto free_return;
	  if (sifted_states[0] != NULL || lim_states[0] != NULL)
	    break;
	  do
	    {
	      --match_last;
	      if (! REG_VALID_INDEX (match_last))
		{
		  ret = REG_NOMATCH;
		  goto free_return;
		}
	    } while (mctx->state_log[match_last] == NULL
		     || !mctx->state_log[match_last]->halt);
	  halt_node = check_halt_state_context (mctx,
						mctx->state_log[match_last],
						match_last);
	}
      ret = merge_state_array (dfa, sifted_states, lim_states,
			       match_last + 1);
      re_free (lim_states);
      lim_states = NULL;
      if (ret != REG_NOERROR)
	goto free_return;
    }
  else
    {
      sift_ctx_init (&sctx, sifted_states, lim_states, halt_node, match_last);
      ret = sift_states_backward (mctx, &sctx);
      re_node_set_free (&sctx.limits);
      if (ret != REG_NOERROR)
	goto free_return;
      if (sifted_states[0] == NULL)
	{
	  ret = REG_NOMATCH;
	  goto free_return;
	}
    }
  re_free (mctx->state_log);
  mctx->state_log = sifted_states;
  sifted_states = NULL;
  mctx->last_node = halt_node;
  mctx->match_last = match_last;
  ret = REG_NOERROR;
 free_return:
  re_free (sifted_states);
  re_free (lim_states);
  return ret;
}

static __inline re_dfastate_t *
acquire_init_state_context (reg_errcode_t *err, const re_match_context_t *mctx,
			    Idx idx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  if (dfa->init_state->has_constraint)
    {
      unsigned int context;
      context = re_string_context_at (&mctx->input, idx - 1, mctx->eflags);
      if (IS_WORD_CONTEXT (context))
	return dfa->init_state_word;
      else if (IS_ORDINARY_CONTEXT (context))
	return dfa->init_state;
      else if (IS_BEGBUF_CONTEXT (context) && IS_NEWLINE_CONTEXT (context))
	return dfa->init_state_begbuf;
      else if (IS_NEWLINE_CONTEXT (context))
	return dfa->init_state_nl;
      else if (IS_BEGBUF_CONTEXT (context))
	{
	  return re_acquire_state_context (err, dfa,
					   dfa->init_state->entrance_nodes,
					   context);
	}
      else
	return dfa->init_state;
    }
  else
    return dfa->init_state;
}

static Idx
check_matching (re_match_context_t *mctx, bool fl_longest_match,
		Idx *p_match_first)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err;
  Idx match = 0;
  Idx match_last = REG_MISSING;
  Idx cur_str_idx = re_string_cur_idx (&mctx->input);
  re_dfastate_t *cur_state;
  bool at_init_state = p_match_first != NULL;
  Idx next_start_idx = cur_str_idx;

  err = REG_NOERROR;
  cur_state = acquire_init_state_context (&err, mctx, cur_str_idx);
  if (cur_state == NULL)
    {
      assert (err == REG_ESPACE);
      return REG_ERROR;
    }

  if (mctx->state_log != NULL)
    {
      mctx->state_log[cur_str_idx] = cur_state;

      if (dfa->nbackref)
	{
	  at_init_state = false;
	  err = check_subexp_matching_top (mctx, &cur_state->nodes, 0);
	  if (err != REG_NOERROR)
	    return err;

	  if (cur_state->has_backref)
	    {
	      err = transit_state_bkref (mctx, &cur_state->nodes);
	      if (err != REG_NOERROR)
	        return err;
	    }
	}
    }

  if (cur_state->halt)
    {
      if (!cur_state->has_constraint
	  || check_halt_state_context (mctx, cur_state, cur_str_idx))
	{
	  if (!fl_longest_match)
	    return cur_str_idx;
	  else
	    {
	      match_last = cur_str_idx;
	      match = 1;
	    }
	}
    }

  while (!re_string_eoi (&mctx->input))
    {
      re_dfastate_t *old_state = cur_state;
      Idx next_char_idx = re_string_cur_idx (&mctx->input) + 1;

      if ((next_char_idx >= mctx->input.bufs_len)
          || ((next_char_idx >= mctx->input.valid_len)
              && mctx->input.valid_len < mctx->input.len))
        {
          err = extend_buffers (mctx);
          if (err != REG_NOERROR)
	    {
	      assert (err == REG_ESPACE);
	      return REG_ERROR;
	    }
        }

      cur_state = transit_state (&err, mctx, cur_state);
      if (mctx->state_log != NULL)
	cur_state = merge_state_with_log (&err, mctx, cur_state);

      if (cur_state == NULL)
	{
	  if (err != REG_NOERROR)
	    return REG_ERROR;

	  if (mctx->state_log == NULL
	      || (match && !fl_longest_match)
	      || (cur_state = find_recover_state (&err, mctx)) == NULL)
	    break;
	}

      if (at_init_state)
	{
	  if (old_state == cur_state)
	    next_start_idx = next_char_idx;
	  else
	    at_init_state = false;
	}

      if (cur_state->halt)
	{
	  if (!cur_state->has_constraint
	      || check_halt_state_context (mctx, cur_state,
					   re_string_cur_idx (&mctx->input)))
	    {
	      match_last = re_string_cur_idx (&mctx->input);
	      match = 1;

	      p_match_first = NULL;
	      if (!fl_longest_match)
		break;
	    }
	}
    }

  if (p_match_first)
    *p_match_first += next_start_idx;

  return match_last;
}

static bool
check_halt_node_context (const re_dfa_t *dfa, Idx node, unsigned int context)
{
  re_token_type_t type = dfa->nodes[node].type;
  unsigned int constraint = dfa->nodes[node].constraint;
  if (type != END_OF_RE)
    return false;
  if (!constraint)
    return true;
  if (NOT_SATISFY_NEXT_CONSTRAINT (constraint, context))
    return false;
  return true;
}

static Idx
check_halt_state_context (const re_match_context_t *mctx,
			  const re_dfastate_t *state, Idx idx)
{
  Idx i;
  unsigned int context;
#ifdef DEBUG
  assert (state->halt);
#endif
  context = re_string_context_at (&mctx->input, idx, mctx->eflags);
  for (i = 0; i < state->nodes.nelem; ++i)
    if (check_halt_node_context (mctx->dfa, state->nodes.elems[i], context))
      return state->nodes.elems[i];
  return 0;
}

static Idx
proceed_next_node (const re_match_context_t *mctx, Idx nregs, regmatch_t *regs,
		   Idx *pidx, Idx node, re_node_set *eps_via_nodes,
		   struct re_fail_stack_t *fs)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx i;
  bool ok;
  if (IS_EPSILON_NODE (dfa->nodes[node].type))
    {
      re_node_set *cur_nodes = &mctx->state_log[*pidx]->nodes;
      re_node_set *edests = &dfa->edests[node];
      Idx dest_node;
      ok = re_node_set_insert (eps_via_nodes, node);
      if (! ok)
	return REG_ERROR;
      for (dest_node = REG_MISSING, i = 0; i < edests->nelem; ++i)
	{
	  Idx candidate = edests->elems[i];
	  if (!re_node_set_contains (cur_nodes, candidate))
	    continue;
          if (dest_node == REG_MISSING)
	    dest_node = candidate;

          else
	    {
	      if (re_node_set_contains (eps_via_nodes, dest_node))
	        return candidate;

	      else if (fs != NULL
		       && push_fail_stack (fs, *pidx, candidate, nregs, regs,
				           eps_via_nodes))
		return REG_ERROR;

	      break;
	    }
	}
      return dest_node;
    }
  else
    {
      Idx naccepted = 0;
      re_token_type_t type = dfa->nodes[node].type;

      if (type == OP_BACK_REF)
	{
	  Idx subexp_idx = dfa->nodes[node].opr.idx + 1;
	  naccepted = regs[subexp_idx].rm_eo - regs[subexp_idx].rm_so;
	  if (fs != NULL)
	    {
	      if (regs[subexp_idx].rm_so == -1 || regs[subexp_idx].rm_eo == -1)
		return REG_MISSING;
	      else if (naccepted)
		{
		  char *buf = (char *) re_string_get_buffer (&mctx->input);
		  if (memcmp (buf + regs[subexp_idx].rm_so, buf + *pidx,
			      naccepted) != 0)
		    return REG_MISSING;
		}
	    }

	  if (naccepted == 0)
	    {
	      Idx dest_node;
	      ok = re_node_set_insert (eps_via_nodes, node);
	      if (! ok)
		return REG_ERROR;
	      dest_node = dfa->edests[node].elems[0];
	      if (re_node_set_contains (&mctx->state_log[*pidx]->nodes,
					dest_node))
		return dest_node;
	    }
	}

      if (naccepted != 0
	  || check_node_accept (mctx, dfa->nodes + node, *pidx))
	{
	  Idx dest_node = dfa->nexts[node];
	  *pidx = (naccepted == 0) ? *pidx + 1 : *pidx + naccepted;
	  if (fs && (*pidx > mctx->match_last || mctx->state_log[*pidx] == NULL
		     || !re_node_set_contains (&mctx->state_log[*pidx]->nodes,
					       dest_node)))
	    return REG_MISSING;
	  re_node_set_empty (eps_via_nodes);
	  return dest_node;
	}
    }
  return REG_MISSING;
}

static reg_errcode_t
push_fail_stack (struct re_fail_stack_t *fs, Idx str_idx, Idx dest_node,
		 Idx nregs, regmatch_t *regs, re_node_set *eps_via_nodes)
{
  reg_errcode_t err;
  Idx num = fs->num++;
  if (fs->num == fs->alloc)
    {
      struct re_fail_stack_ent_t *new_array;
      new_array = realloc (fs->stack, (sizeof (struct re_fail_stack_ent_t)
				       * fs->alloc * 2));
      if (new_array == NULL)
	return REG_ESPACE;
      fs->alloc *= 2;
      fs->stack = new_array;
    }
  fs->stack[num].idx = str_idx;
  fs->stack[num].node = dest_node;
  fs->stack[num].regs = re_malloc (regmatch_t, nregs);
  if (fs->stack[num].regs == NULL)
    return REG_ESPACE;
  memcpy (fs->stack[num].regs, regs, sizeof (regmatch_t) * nregs);
  err = re_node_set_init_copy (&fs->stack[num].eps_via_nodes, eps_via_nodes);
  return err;
}

static Idx
pop_fail_stack (struct re_fail_stack_t *fs, Idx *pidx, Idx nregs,
		regmatch_t *regs, re_node_set *eps_via_nodes)
{
  Idx num = --fs->num;
  assert (REG_VALID_INDEX (num));
  *pidx = fs->stack[num].idx;
  memcpy (regs, fs->stack[num].regs, sizeof (regmatch_t) * nregs);
  re_node_set_free (eps_via_nodes);
  re_free (fs->stack[num].regs);
  *eps_via_nodes = fs->stack[num].eps_via_nodes;
  return fs->stack[num].node;
}

static reg_errcode_t
set_regs (const regex_t *preg, const re_match_context_t *mctx, size_t nmatch,
	  regmatch_t *pmatch, bool fl_backtrack)
{
  const re_dfa_t *dfa = (const re_dfa_t *) preg->buffer;
  Idx idx, cur_node;
  re_node_set eps_via_nodes;
  struct re_fail_stack_t *fs;
  struct re_fail_stack_t fs_body = { 0, 2, NULL };
  regmatch_t *prev_idx_match;
  bool prev_idx_match_malloced = false;

#ifdef DEBUG
  assert (nmatch > 1);
  assert (mctx->state_log != NULL);
#endif
  if (fl_backtrack)
    {
      fs = &fs_body;
      fs->stack = re_malloc (struct re_fail_stack_ent_t, fs->alloc);
      if (fs->stack == NULL)
	return REG_ESPACE;
    }
  else
    fs = NULL;

  cur_node = dfa->init_node;
  re_node_set_init_empty (&eps_via_nodes);

  if (__libc_use_alloca (nmatch * sizeof (regmatch_t)))
    prev_idx_match = (regmatch_t *) _alloca (nmatch * sizeof (regmatch_t));
  else
    {
      prev_idx_match = re_malloc (regmatch_t, nmatch);
      if (prev_idx_match == NULL)
	{
	  free_fail_stack_return (fs);
	  return REG_ESPACE;
	}
      prev_idx_match_malloced = true;
    }
  memcpy (prev_idx_match, pmatch, sizeof (regmatch_t) * nmatch);

  for (idx = (unsigned int)pmatch[0].rm_so; idx <= (unsigned int)pmatch[0].rm_eo ;)
    {
      update_regs (dfa, pmatch, prev_idx_match, cur_node, idx, nmatch);

      if (idx == (unsigned int)pmatch[0].rm_eo && cur_node == mctx->last_node)
	{
	  Idx reg_idx;
	  if (fs)
	    {
	      for (reg_idx = 0; reg_idx < nmatch; ++reg_idx)
		if (pmatch[reg_idx].rm_so > -1 && pmatch[reg_idx].rm_eo == -1)
		  break;
	      if (reg_idx == nmatch)
		{
		  re_node_set_free (&eps_via_nodes);
		  if (prev_idx_match_malloced)
		    re_free (prev_idx_match);
		  return free_fail_stack_return (fs);
		}
	      cur_node = pop_fail_stack (fs, &idx, nmatch, pmatch,
					 &eps_via_nodes);
	    }
	  else
	    {
	      re_node_set_free (&eps_via_nodes);
	      if (prev_idx_match_malloced)
		re_free (prev_idx_match);
	      return REG_NOERROR;
	    }
	}

      cur_node = proceed_next_node (mctx, nmatch, pmatch, &idx, cur_node,
				    &eps_via_nodes, fs);

      if (! REG_VALID_INDEX (cur_node))
	{
	  if (cur_node == REG_ERROR)
	    {
	      re_node_set_free (&eps_via_nodes);
	      if (prev_idx_match_malloced)
		re_free (prev_idx_match);
	      free_fail_stack_return (fs);
	      return REG_ESPACE;
	    }
	  if (fs)
	    cur_node = pop_fail_stack (fs, &idx, nmatch, pmatch,
				       &eps_via_nodes);
	  else
	    {
	      re_node_set_free (&eps_via_nodes);
	      if (prev_idx_match_malloced)
		re_free (prev_idx_match);
	      return REG_NOMATCH;
	    }
	}
    }
  re_node_set_free (&eps_via_nodes);
  if (prev_idx_match_malloced)
    re_free (prev_idx_match);
  return free_fail_stack_return (fs);
}

static reg_errcode_t
free_fail_stack_return (struct re_fail_stack_t *fs)
{
  if (fs)
    {
      Idx fs_idx;
      for (fs_idx = 0; fs_idx < fs->num; ++fs_idx)
	{
	  re_node_set_free (&fs->stack[fs_idx].eps_via_nodes);
	  re_free (fs->stack[fs_idx].regs);
	}
      re_free (fs->stack);
    }
  return REG_NOERROR;
}

static void
update_regs (const re_dfa_t *dfa, regmatch_t *pmatch,
	     regmatch_t *prev_idx_match, Idx cur_node, Idx cur_idx, Idx nmatch)
{
  int type = dfa->nodes[cur_node].type;
  if (type == OP_OPEN_SUBEXP)
    {
      Idx reg_num = dfa->nodes[cur_node].opr.idx + 1;

      if (reg_num < nmatch)
	{
	  pmatch[reg_num].rm_so = cur_idx;
	  pmatch[reg_num].rm_eo = -1;
	}
    }
  else if (type == OP_CLOSE_SUBEXP)
    {
      Idx reg_num = dfa->nodes[cur_node].opr.idx + 1;
      if (reg_num < nmatch)
	{
	  if ((unsigned int)pmatch[reg_num].rm_so < cur_idx)
	    {
	      pmatch[reg_num].rm_eo = cur_idx;
	      memcpy (prev_idx_match, pmatch, sizeof (regmatch_t) * nmatch);
	    }
	  else
	    {
	      if (dfa->nodes[cur_node].opt_subexp
		  && prev_idx_match[reg_num].rm_so != -1)
		memcpy (pmatch, prev_idx_match, sizeof (regmatch_t) * nmatch);
	      else
		pmatch[reg_num].rm_eo = cur_idx;
	    }
	}
    }
}

#define STATE_NODE_CONTAINS(state,node) \
  ((state) != NULL && re_node_set_contains (&(state)->nodes, node))

static reg_errcode_t
sift_states_backward (const re_match_context_t *mctx, re_sift_context_t *sctx)
{
  reg_errcode_t err;
  int null_cnt = 0;
  Idx str_idx = sctx->last_str_idx;
  re_node_set cur_dest;

#ifdef DEBUG
  assert (mctx->state_log != NULL && mctx->state_log[str_idx] != NULL);
#endif

  err = re_node_set_init_1 (&cur_dest, sctx->last_node);
  if (err != REG_NOERROR)
    return err;
  err = update_cur_sifted_state (mctx, sctx, str_idx, &cur_dest);
  if (err != REG_NOERROR)
    goto free_return;

  while (str_idx > 0)
    {
      null_cnt = (sctx->sifted_states[str_idx] == NULL) ? null_cnt + 1 : 0;
      if (null_cnt > mctx->max_mb_elem_len)
	{
	  memset (sctx->sifted_states, '\0',
		  sizeof (re_dfastate_t *) * str_idx);
	  re_node_set_free (&cur_dest);
	  return REG_NOERROR;
	}
      re_node_set_empty (&cur_dest);
      --str_idx;

      if (mctx->state_log[str_idx])
	{
	  err = build_sifted_states (mctx, sctx, str_idx, &cur_dest);
          if (err != REG_NOERROR)
	    goto free_return;
	}

      err = update_cur_sifted_state (mctx, sctx, str_idx, &cur_dest);
      if (err != REG_NOERROR)
	goto free_return;
    }
  err = REG_NOERROR;
 free_return:
  re_node_set_free (&cur_dest);
  return err;
}

static reg_errcode_t
build_sifted_states (const re_match_context_t *mctx, re_sift_context_t *sctx,
		     Idx str_idx, re_node_set *cur_dest)
{
  const re_dfa_t *const dfa = mctx->dfa;
  const re_node_set *cur_src = &mctx->state_log[str_idx]->non_eps_nodes;
  Idx i;

  for (i = 0; i < cur_src->nelem; i++)
    {
      Idx prev_node = cur_src->elems[i];
      int naccepted = 0;
      bool ok;

#ifdef DEBUG
      re_token_type_t type = dfa->nodes[prev_node].type;
      assert (!IS_EPSILON_NODE (type));
#endif
      if (!naccepted
	  && check_node_accept (mctx, dfa->nodes + prev_node, str_idx)
	  && STATE_NODE_CONTAINS (sctx->sifted_states[str_idx + 1],
				  dfa->nexts[prev_node]))
	naccepted = 1;

      if (naccepted == 0)
	continue;

      if (sctx->limits.nelem)
	{
	  Idx to_idx = str_idx + naccepted;
	  if (check_dst_limits (mctx, &sctx->limits,
				dfa->nexts[prev_node], to_idx,
				prev_node, str_idx))
	    continue;
	}
      ok = re_node_set_insert (cur_dest, prev_node);
      if (! ok)
	return REG_ESPACE;
    }

  return REG_NOERROR;
}

static reg_errcode_t
clean_state_log_if_needed (re_match_context_t *mctx, Idx next_state_log_idx)
{
  Idx top = mctx->state_log_top;

  if (next_state_log_idx >= mctx->input.bufs_len
      || (next_state_log_idx >= mctx->input.valid_len
	  && mctx->input.valid_len < mctx->input.len))
    {
      reg_errcode_t err;
      err = extend_buffers (mctx);
      if (err != REG_NOERROR)
	return err;
    }

  if (top < next_state_log_idx)
    {
      memset (mctx->state_log + top + 1, '\0',
	      sizeof (re_dfastate_t *) * (next_state_log_idx - top));
      mctx->state_log_top = next_state_log_idx;
    }
  return REG_NOERROR;
}

static reg_errcode_t
merge_state_array (const re_dfa_t *dfa, re_dfastate_t **dst,
		   re_dfastate_t **src, Idx num)
{
  Idx st_idx;
  reg_errcode_t err;
  for (st_idx = 0; st_idx < num; ++st_idx)
    {
      if (dst[st_idx] == NULL)
	dst[st_idx] = src[st_idx];
      else if (src[st_idx] != NULL)
	{
	  re_node_set merged_set;
	  err = re_node_set_init_union (&merged_set, &dst[st_idx]->nodes,
					&src[st_idx]->nodes);
	  if (err != REG_NOERROR)
	    return err;
	  dst[st_idx] = re_acquire_state (&err, dfa, &merged_set);
	  re_node_set_free (&merged_set);
	  if (err != REG_NOERROR)
	    return err;
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
update_cur_sifted_state (const re_match_context_t *mctx,
			 re_sift_context_t *sctx, Idx str_idx,
			 re_node_set *dest_nodes)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err = REG_NOERROR;
  const re_node_set *candidates;
  candidates = ((mctx->state_log[str_idx] == NULL) ? NULL
		: &mctx->state_log[str_idx]->nodes);

  if (dest_nodes->nelem == 0)
    sctx->sifted_states[str_idx] = NULL;
  else
    {
      if (candidates)
	{
	  err = add_epsilon_src_nodes (dfa, dest_nodes, candidates);
	  if (err != REG_NOERROR)
	    return err;

	  if (sctx->limits.nelem)
	    {
	      err = check_subexp_limits (dfa, dest_nodes, candidates, &sctx->limits,
					 mctx->bkref_ents, str_idx);
	      if (err != REG_NOERROR)
		return err;
	    }
	}

      sctx->sifted_states[str_idx] = re_acquire_state (&err, dfa, dest_nodes);
      if (err != REG_NOERROR)
	return err;
    }

  if (candidates && mctx->state_log[str_idx]->has_backref)
    {
      err = sift_states_bkref (mctx, sctx, str_idx, candidates);
      if (err != REG_NOERROR)
	return err;
    }
  return REG_NOERROR;
}

static reg_errcode_t
add_epsilon_src_nodes (const re_dfa_t *dfa, re_node_set *dest_nodes,
		       const re_node_set *candidates)
{
  reg_errcode_t err = REG_NOERROR;
  Idx i;

  re_dfastate_t *state = re_acquire_state (&err, dfa, dest_nodes);
  if (err != REG_NOERROR)
    return err;

  if (!state->inveclosure.alloc)
    {
      err = re_node_set_alloc (&state->inveclosure, dest_nodes->nelem);
      if (err != REG_NOERROR)
        return REG_ESPACE;
      for (i = 0; i < dest_nodes->nelem; i++)
        re_node_set_merge (&state->inveclosure,
			   dfa->inveclosures + dest_nodes->elems[i]);
    }
  return re_node_set_add_intersect (dest_nodes, candidates,
				    &state->inveclosure);
}

static reg_errcode_t
sub_epsilon_src_nodes (const re_dfa_t *dfa, Idx node, re_node_set *dest_nodes,
		       const re_node_set *candidates)
{
    Idx ecl_idx;
    reg_errcode_t err;
    re_node_set *inv_eclosure = dfa->inveclosures + node;
    re_node_set except_nodes;
    re_node_set_init_empty (&except_nodes);
    for (ecl_idx = 0; ecl_idx < inv_eclosure->nelem; ++ecl_idx)
      {
	Idx cur_node = inv_eclosure->elems[ecl_idx];
	if (cur_node == node)
	  continue;
	if (IS_EPSILON_NODE (dfa->nodes[cur_node].type))
	  {
	    Idx edst1 = dfa->edests[cur_node].elems[0];
	    Idx edst2 = ((dfa->edests[cur_node].nelem > 1)
			 ? dfa->edests[cur_node].elems[1] : REG_MISSING);
	    if ((!re_node_set_contains (inv_eclosure, edst1)
		 && re_node_set_contains (dest_nodes, edst1))
		|| (REG_VALID_NONZERO_INDEX (edst2)
		    && !re_node_set_contains (inv_eclosure, edst2)
		    && re_node_set_contains (dest_nodes, edst2)))
	      {
		err = re_node_set_add_intersect (&except_nodes, candidates,
						 dfa->inveclosures + cur_node);
		if (err != REG_NOERROR)
		  {
		    re_node_set_free (&except_nodes);
		    return err;
		  }
	      }
	  }
      }
    for (ecl_idx = 0; ecl_idx < inv_eclosure->nelem; ++ecl_idx)
      {
	Idx cur_node = inv_eclosure->elems[ecl_idx];
	if (!re_node_set_contains (&except_nodes, cur_node))
	  {
	    Idx idx = re_node_set_contains (dest_nodes, cur_node) - 1;
	    re_node_set_remove_at (dest_nodes, idx);
	  }
      }
    re_node_set_free (&except_nodes);
    return REG_NOERROR;
}

static bool
check_dst_limits (const re_match_context_t *mctx, const re_node_set *limits,
		  Idx dst_node, Idx dst_idx, Idx src_node, Idx src_idx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx lim_idx, src_pos, dst_pos;

  Idx dst_bkref_idx = search_cur_bkref_entry (mctx, dst_idx);
  Idx src_bkref_idx = search_cur_bkref_entry (mctx, src_idx);
  for (lim_idx = 0; lim_idx < limits->nelem; ++lim_idx)
    {
      Idx subexp_idx;
      struct re_backref_cache_entry *ent;
      ent = mctx->bkref_ents + limits->elems[lim_idx];
      subexp_idx = dfa->nodes[ent->node].opr.idx;

      dst_pos = check_dst_limits_calc_pos (mctx, limits->elems[lim_idx],
					   subexp_idx, dst_node, dst_idx,
					   dst_bkref_idx);
      src_pos = check_dst_limits_calc_pos (mctx, limits->elems[lim_idx],
					   subexp_idx, src_node, src_idx,
					   src_bkref_idx);

      if (src_pos == dst_pos)
	continue;
      else
	return true;
    }
  return false;
}

static int
check_dst_limits_calc_pos_1 (const re_match_context_t *mctx, int boundaries,
			     Idx subexp_idx, Idx from_node, Idx bkref_idx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  const re_node_set *eclosures = dfa->eclosures + from_node;
  Idx node_idx;

  for (node_idx = 0; node_idx < eclosures->nelem; ++node_idx)
    {
      Idx node = eclosures->elems[node_idx];
      switch (dfa->nodes[node].type)
	{
	case OP_BACK_REF:
	  if (bkref_idx != REG_MISSING)
	    {
	      struct re_backref_cache_entry *ent = mctx->bkref_ents + bkref_idx;
	      do
	        {
		  Idx dst;
		  int cpos;

		  if (ent->node != node)
		    continue;

		  if (subexp_idx < BITSET_WORD_BITS
		      && !(ent->eps_reachable_subexps_map
			   & ((bitset_word_t) 1 << subexp_idx)))
		    continue;

		  dst = dfa->edests[node].elems[0];
		  if (dst == from_node)
		    {
		      if (boundaries & 1)
		        return -1;
		      else
		        return 0;
		    }

		  cpos =
		    check_dst_limits_calc_pos_1 (mctx, boundaries, subexp_idx,
						 dst, bkref_idx);
		  if (cpos == -1)
		    return -1;
		  if (cpos == 0 && (boundaries & 2))
		    return 0;

		  if (subexp_idx < BITSET_WORD_BITS)
		    ent->eps_reachable_subexps_map
		      &= ~((bitset_word_t) 1 << subexp_idx);
	        }
	      while (ent++->more);
	    }
	  break;

	case OP_OPEN_SUBEXP:
	  if ((boundaries & 1) && subexp_idx == dfa->nodes[node].opr.idx)
	    return -1;
	  break;

	case OP_CLOSE_SUBEXP:
	  if ((boundaries & 2) && subexp_idx == dfa->nodes[node].opr.idx)
	    return 0;
	  break;

	default:
	    break;
	}
    }

  return (boundaries & 2) ? 1 : 0;
}

static int
check_dst_limits_calc_pos (const re_match_context_t *mctx, Idx limit,
			   Idx subexp_idx, Idx from_node, Idx str_idx,
			   Idx bkref_idx)
{
  struct re_backref_cache_entry *lim = mctx->bkref_ents + limit;
  int boundaries;

  if (str_idx < lim->subexp_from)
    return -1;

  if (lim->subexp_to < str_idx)
    return 1;

  boundaries = (str_idx == lim->subexp_from);
  boundaries |= (str_idx == lim->subexp_to) << 1;
  if (boundaries == 0)
    return 0;

  return check_dst_limits_calc_pos_1 (mctx, boundaries, subexp_idx,
				      from_node, bkref_idx);
}

static reg_errcode_t
check_subexp_limits (const re_dfa_t *dfa, re_node_set *dest_nodes,
		     const re_node_set *candidates, re_node_set *limits,
		     struct re_backref_cache_entry *bkref_ents, Idx str_idx)
{
  reg_errcode_t err;
  Idx node_idx, lim_idx;

  for (lim_idx = 0; lim_idx < limits->nelem; ++lim_idx)
    {
      Idx subexp_idx;
      struct re_backref_cache_entry *ent;
      ent = bkref_ents + limits->elems[lim_idx];

      if (str_idx <= ent->subexp_from || ent->str_idx < str_idx)
	continue;

      subexp_idx = dfa->nodes[ent->node].opr.idx;
      if (ent->subexp_to == str_idx)
	{
	  Idx ops_node = REG_MISSING;
	  Idx cls_node = REG_MISSING;
	  for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
	    {
	      Idx node = dest_nodes->elems[node_idx];
	      re_token_type_t type = dfa->nodes[node].type;
	      if (type == OP_OPEN_SUBEXP
		  && subexp_idx == dfa->nodes[node].opr.idx)
		ops_node = node;
	      else if (type == OP_CLOSE_SUBEXP
		       && subexp_idx == dfa->nodes[node].opr.idx)
		cls_node = node;
	    }

	  if (REG_VALID_INDEX (ops_node))
	    {
	      err = sub_epsilon_src_nodes (dfa, ops_node, dest_nodes,
					   candidates);
	      if (err != REG_NOERROR)
		return err;
	    }

	  if (REG_VALID_INDEX (cls_node))
	    for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
	      {
		Idx node = dest_nodes->elems[node_idx];
		if (!re_node_set_contains (dfa->inveclosures + node,
					   cls_node)
		    && !re_node_set_contains (dfa->eclosures + node,
					      cls_node))
		  {
		    err = sub_epsilon_src_nodes (dfa, node, dest_nodes,
						 candidates);
		    if (err != REG_NOERROR)
		      return err;
		    --node_idx;
		  }
	      }
	}
      else
	{
	  for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
	    {
	      Idx node = dest_nodes->elems[node_idx];
	      re_token_type_t type = dfa->nodes[node].type;
	      if (type == OP_CLOSE_SUBEXP || type == OP_OPEN_SUBEXP)
		{
		  if (subexp_idx != dfa->nodes[node].opr.idx)
		    continue;
		  err = sub_epsilon_src_nodes (dfa, node, dest_nodes,
					       candidates);
		  if (err != REG_NOERROR)
		    return err;
		}
	    }
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
sift_states_bkref (const re_match_context_t *mctx, re_sift_context_t *sctx,
		   Idx str_idx, const re_node_set *candidates)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err;
  Idx node_idx, node;
  re_sift_context_t local_sctx;
  Idx first_idx = search_cur_bkref_entry (mctx, str_idx);

  if (first_idx == REG_MISSING)
    return REG_NOERROR;

  local_sctx.sifted_states = NULL;

  for (node_idx = 0; node_idx < candidates->nelem; ++node_idx)
    {
      Idx enabled_idx;
      re_token_type_t type;
      struct re_backref_cache_entry *entry;
      node = candidates->elems[node_idx];
      type = dfa->nodes[node].type;
      if (node == sctx->last_node && str_idx == sctx->last_str_idx)
	continue;
      if (type != OP_BACK_REF)
	continue;

      entry = mctx->bkref_ents + first_idx;
      enabled_idx = first_idx;
      do
	{
	  Idx subexp_len;
	  Idx to_idx;
	  Idx dst_node;
	  bool ok;
	  re_dfastate_t *cur_state;

	  if (entry->node != node)
	    continue;
	  subexp_len = entry->subexp_to - entry->subexp_from;
	  to_idx = str_idx + subexp_len;
	  dst_node = (subexp_len ? dfa->nexts[node]
		      : dfa->edests[node].elems[0]);

	  if (to_idx > sctx->last_str_idx
	      || sctx->sifted_states[to_idx] == NULL
	      || !STATE_NODE_CONTAINS (sctx->sifted_states[to_idx], dst_node)
	      || check_dst_limits (mctx, &sctx->limits, node,
				   str_idx, dst_node, to_idx))
	    continue;

	  if (local_sctx.sifted_states == NULL)
	    {
	      local_sctx = *sctx;
	      err = re_node_set_init_copy (&local_sctx.limits, &sctx->limits);
	      if (err != REG_NOERROR)
		goto free_return;
	    }
	  local_sctx.last_node = node;
	  local_sctx.last_str_idx = str_idx;
	  ok = re_node_set_insert (&local_sctx.limits, enabled_idx);
	  if (! ok)
	    {
	      err = REG_ESPACE;
	      goto free_return;
	    }
	  cur_state = local_sctx.sifted_states[str_idx];
	  err = sift_states_backward (mctx, &local_sctx);
	  if (err != REG_NOERROR)
	    goto free_return;
	  if (sctx->limited_states != NULL)
	    {
	      err = merge_state_array (dfa, sctx->limited_states,
				       local_sctx.sifted_states,
				       str_idx + 1);
	      if (err != REG_NOERROR)
		goto free_return;
	    }
	  local_sctx.sifted_states[str_idx] = cur_state;
	  re_node_set_remove (&local_sctx.limits, enabled_idx);

          entry = mctx->bkref_ents + enabled_idx;
	}
      while (enabled_idx++, entry++->more);
    }
  err = REG_NOERROR;
 free_return:
  if (local_sctx.sifted_states != NULL)
    {
      re_node_set_free (&local_sctx.limits);
    }

  return err;
}

static re_dfastate_t *
transit_state (reg_errcode_t *err, re_match_context_t *mctx,
	       re_dfastate_t *state)
{
  re_dfastate_t **trtable;
  unsigned char ch;

  ch = re_string_fetch_byte (&mctx->input);
  for (;;)
    {
      trtable = state->trtable;
      if (trtable != NULL)
	return trtable[ch];

      trtable = state->word_trtable;
      if (trtable != NULL)
        {
	  unsigned int context;
	  context
	    = re_string_context_at (&mctx->input,
				    re_string_cur_idx (&mctx->input) - 1,
				    mctx->eflags);
	  if (IS_WORD_CONTEXT (context))
	    return trtable[ch + SBC_MAX];
	  else
	    return trtable[ch];
	}

      if (!build_trtable (mctx->dfa, state))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
    }
}

static re_dfastate_t *
merge_state_with_log (reg_errcode_t *err, re_match_context_t *mctx,
		      re_dfastate_t *next_state)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx cur_idx = re_string_cur_idx (&mctx->input);

  if (cur_idx > mctx->state_log_top)
    {
      mctx->state_log[cur_idx] = next_state;
      mctx->state_log_top = cur_idx;
    }
  else if (mctx->state_log[cur_idx] == 0)
    {
      mctx->state_log[cur_idx] = next_state;
    }
  else
    {
      re_dfastate_t *pstate;
      unsigned int context;
      re_node_set next_nodes, *log_nodes, *table_nodes = NULL;
      pstate = mctx->state_log[cur_idx];
      log_nodes = pstate->entrance_nodes;
      if (next_state != NULL)
        {
          table_nodes = next_state->entrance_nodes;
          *err = re_node_set_init_union (&next_nodes, table_nodes,
					     log_nodes);
          if (*err != REG_NOERROR)
	    return NULL;
        }
      else
        next_nodes = *log_nodes;

      context = re_string_context_at (&mctx->input,
				      re_string_cur_idx (&mctx->input) - 1,
				      mctx->eflags);
      next_state = mctx->state_log[cur_idx]
        = re_acquire_state_context (err, dfa, &next_nodes, context);

      if (table_nodes != NULL)
        re_node_set_free (&next_nodes);
    }

  if (dfa->nbackref && next_state != NULL)
    {
      *err = check_subexp_matching_top (mctx, &next_state->nodes,
					cur_idx);
      if (*err != REG_NOERROR)
	return NULL;

      if (next_state->has_backref)
	{
	  *err = transit_state_bkref (mctx, &next_state->nodes);
	  if (*err != REG_NOERROR)
	    return NULL;
	  next_state = mctx->state_log[cur_idx];
	}
    }

  return next_state;
}

static re_dfastate_t *
find_recover_state (reg_errcode_t *err, re_match_context_t *mctx)
{
  re_dfastate_t *cur_state;
  do
    {
      Idx max = mctx->state_log_top;
      Idx cur_str_idx = re_string_cur_idx (&mctx->input);

      do
	{
          if (++cur_str_idx > max)
            return NULL;
          re_string_skip_bytes (&mctx->input, 1);
	}
      while (mctx->state_log[cur_str_idx] == NULL);

      cur_state = merge_state_with_log (err, mctx, NULL);
    }
  while (*err == REG_NOERROR && cur_state == NULL);
  return cur_state;
}

static reg_errcode_t
check_subexp_matching_top (re_match_context_t *mctx, re_node_set *cur_nodes,
			   Idx str_idx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx node_idx;
  reg_errcode_t err;

  for (node_idx = 0; node_idx < cur_nodes->nelem; ++node_idx)
    {
      Idx node = cur_nodes->elems[node_idx];
      if (dfa->nodes[node].type == OP_OPEN_SUBEXP
	  && dfa->nodes[node].opr.idx < BITSET_WORD_BITS
	  && (dfa->used_bkref_map
	      & ((bitset_word_t) 1 << dfa->nodes[node].opr.idx)))
	{
	  err = match_ctx_add_subtop (mctx, node, str_idx);
	  if (err != REG_NOERROR)
	    return err;
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
transit_state_bkref (re_match_context_t *mctx, const re_node_set *nodes)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err;
  Idx i;
  Idx cur_str_idx = re_string_cur_idx (&mctx->input);

  for (i = 0; i < nodes->nelem; ++i)
    {
      Idx dest_str_idx, prev_nelem, bkc_idx;
      Idx node_idx = nodes->elems[i];
      unsigned int context;
      const re_token_t *node = dfa->nodes + node_idx;
      re_node_set *new_dest_nodes;

      if (node->type != OP_BACK_REF)
	continue;

      if (node->constraint)
	{
	  context = re_string_context_at (&mctx->input, cur_str_idx,
					  mctx->eflags);
	  if (NOT_SATISFY_NEXT_CONSTRAINT (node->constraint, context))
	    continue;
	}

      bkc_idx = mctx->nbkref_ents;
      err = get_subexp (mctx, node_idx, cur_str_idx);
      if (err != REG_NOERROR)
	goto free_return;

#ifdef DEBUG
      assert (dfa->nexts[node_idx] != REG_MISSING);
#endif
      for (; bkc_idx < mctx->nbkref_ents; ++bkc_idx)
	{
	  Idx subexp_len;
	  re_dfastate_t *dest_state;
	  struct re_backref_cache_entry *bkref_ent;
	  bkref_ent = mctx->bkref_ents + bkc_idx;
	  if (bkref_ent->node != node_idx || bkref_ent->str_idx != cur_str_idx)
	    continue;
	  subexp_len = bkref_ent->subexp_to - bkref_ent->subexp_from;
	  new_dest_nodes = (subexp_len == 0
			    ? dfa->eclosures + dfa->edests[node_idx].elems[0]
			    : dfa->eclosures + dfa->nexts[node_idx]);
	  dest_str_idx = (cur_str_idx + bkref_ent->subexp_to
			  - bkref_ent->subexp_from);
	  context = re_string_context_at (&mctx->input, dest_str_idx - 1,
					  mctx->eflags);
	  dest_state = mctx->state_log[dest_str_idx];
	  prev_nelem = ((mctx->state_log[cur_str_idx] == NULL) ? 0
			: mctx->state_log[cur_str_idx]->nodes.nelem);
	  if (dest_state == NULL)
	    {
	      mctx->state_log[dest_str_idx]
		= re_acquire_state_context (&err, dfa, new_dest_nodes,
					    context);
	      if (mctx->state_log[dest_str_idx] == NULL
		      && err != REG_NOERROR)
		goto free_return;
	    }
	  else
	    {
	      re_node_set dest_nodes;
	      err = re_node_set_init_union (&dest_nodes,
					    dest_state->entrance_nodes,
					    new_dest_nodes);
	      if (err != REG_NOERROR)
		{
		  re_node_set_free (&dest_nodes);
		  goto free_return;
		}
	      mctx->state_log[dest_str_idx]
		= re_acquire_state_context (&err, dfa, &dest_nodes, context);
	      re_node_set_free (&dest_nodes);
	      if (mctx->state_log[dest_str_idx] == NULL
		      && err != REG_NOERROR)
		goto free_return;
	    }
	  if (subexp_len == 0
	      && mctx->state_log[cur_str_idx]->nodes.nelem > prev_nelem)
	    {
	      err = check_subexp_matching_top (mctx, new_dest_nodes,
					       cur_str_idx);
	      if (err != REG_NOERROR)
		goto free_return;
	      err = transit_state_bkref (mctx, new_dest_nodes);
	      if (err != REG_NOERROR)
		goto free_return;
	    }
	}
    }
  err = REG_NOERROR;
 free_return:
  return err;
}

static reg_errcode_t
get_subexp (re_match_context_t *mctx, Idx bkref_node, Idx bkref_str_idx)
{
  const re_dfa_t *const dfa = mctx->dfa;
  Idx subexp_num, sub_top_idx;
  const char *buf = (const char *) re_string_get_buffer (&mctx->input);
  Idx cache_idx = search_cur_bkref_entry (mctx, bkref_str_idx);
  if (cache_idx != REG_MISSING)
    {
      const struct re_backref_cache_entry *entry
	= mctx->bkref_ents + cache_idx;
      do
        if (entry->node == bkref_node)
	  return REG_NOERROR;
      while (entry++->more);
    }

  subexp_num = dfa->nodes[bkref_node].opr.idx;

  for (sub_top_idx = 0; sub_top_idx < mctx->nsub_tops; ++sub_top_idx)
    {
      reg_errcode_t err;
      re_sub_match_top_t *sub_top = mctx->sub_tops[sub_top_idx];
      re_sub_match_last_t *sub_last;
      Idx sub_last_idx, sl_str, bkref_str_off;

      if (dfa->nodes[sub_top->node].opr.idx != subexp_num)
	continue;

      sl_str = sub_top->str_idx;
      bkref_str_off = bkref_str_idx;
      for (sub_last_idx = 0; sub_last_idx < sub_top->nlasts; ++sub_last_idx)
	{
	  regoff_t sl_str_diff;
	  sub_last = sub_top->lasts[sub_last_idx];
	  sl_str_diff = sub_last->str_idx - sl_str;
	  if (sl_str_diff > 0)
	    {
	      if (bkref_str_off + sl_str_diff > mctx->input.valid_len)
		{
		  if (bkref_str_off + sl_str_diff > mctx->input.len)
		    break;

		  err = clean_state_log_if_needed (mctx,
						   bkref_str_off
						   + sl_str_diff);
		  if (err != REG_NOERROR)
		    return err;
		  buf = (const char *) re_string_get_buffer (&mctx->input);
		}
	      if (memcmp (buf + bkref_str_off, buf + sl_str, sl_str_diff) != 0)
		break;
	    }
	  bkref_str_off += sl_str_diff;
	  sl_str += sl_str_diff;
	  err = get_subexp_sub (mctx, sub_top, sub_last, bkref_node,
				bkref_str_idx);

	  buf = (const char *) re_string_get_buffer (&mctx->input);

	  if (err == REG_NOMATCH)
	    continue;
	  if (err != REG_NOERROR)
	    return err;
	}

      if (sub_last_idx < sub_top->nlasts)
	continue;
      if (sub_last_idx > 0)
	++sl_str;
      for (; sl_str <= bkref_str_idx; ++sl_str)
	{
	  Idx cls_node;
	  regoff_t sl_str_off;
	  const re_node_set *nodes;
	  sl_str_off = sl_str - sub_top->str_idx;
	  if (sl_str_off > 0)
	    {
	      if (bkref_str_off >= mctx->input.valid_len)
		{
		  if (bkref_str_off >= mctx->input.len)
		    break;

		  err = extend_buffers (mctx);
		  if (err != REG_NOERROR)
		    return err;

		  buf = (const char *) re_string_get_buffer (&mctx->input);
		}
	      if (buf [bkref_str_off++] != buf[sl_str - 1])
		break;
	    }
	  if (mctx->state_log[sl_str] == NULL)
	    continue;
	  nodes = &mctx->state_log[sl_str]->nodes;
	  cls_node = find_subexp_node (dfa, nodes, subexp_num,
				       OP_CLOSE_SUBEXP);
	  if (cls_node == REG_MISSING)
	    continue;
	  if (sub_top->path == NULL)
	    {
	      sub_top->path = calloc (sizeof (state_array_t),
				      sl_str - sub_top->str_idx + 1);
	      if (sub_top->path == NULL)
		return REG_ESPACE;
	    }
	  err = check_arrival (mctx, sub_top->path, sub_top->node,
			       sub_top->str_idx, cls_node, sl_str,
			       OP_CLOSE_SUBEXP);
	  if (err == REG_NOMATCH)
	      continue;
	  if (err != REG_NOERROR)
	      return err;
	  sub_last = match_ctx_add_sublast (sub_top, cls_node, sl_str);
	  if (sub_last == NULL)
	    return REG_ESPACE;
	  err = get_subexp_sub (mctx, sub_top, sub_last, bkref_node,
				bkref_str_idx);
	  if (err == REG_NOMATCH)
	    continue;
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
get_subexp_sub (re_match_context_t *mctx, const re_sub_match_top_t *sub_top,
		re_sub_match_last_t *sub_last, Idx bkref_node, Idx bkref_str)
{
  reg_errcode_t err;
  Idx to_idx;
  err = check_arrival (mctx, &sub_last->path, sub_last->node,
		       sub_last->str_idx, bkref_node, bkref_str,
		       OP_OPEN_SUBEXP);
  if (err != REG_NOERROR)
    return err;
  err = match_ctx_add_entry (mctx, bkref_node, bkref_str, sub_top->str_idx,
			     sub_last->str_idx);
  if (err != REG_NOERROR)
    return err;
  to_idx = bkref_str + sub_last->str_idx - sub_top->str_idx;
  return clean_state_log_if_needed (mctx, to_idx);
}

static Idx
find_subexp_node (const re_dfa_t *dfa, const re_node_set *nodes,
		  Idx subexp_idx, int type)
{
  Idx cls_idx;
  for (cls_idx = 0; cls_idx < nodes->nelem; ++cls_idx)
    {
      Idx cls_node = nodes->elems[cls_idx];
      const re_token_t *node = dfa->nodes + cls_node;
      if (node->type == type
	  && node->opr.idx == subexp_idx)
	return cls_node;
    }
  return REG_MISSING;
}

static reg_errcode_t
check_arrival (re_match_context_t *mctx, state_array_t *path, Idx top_node,
	       Idx top_str, Idx last_node, Idx last_str, int type)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err = REG_NOERROR;
  Idx subexp_num, backup_cur_idx, str_idx, null_cnt;
  re_dfastate_t *cur_state = NULL;
  re_node_set *cur_nodes, next_nodes;
  re_dfastate_t **backup_state_log;
  unsigned int context;

  subexp_num = dfa->nodes[top_node].opr.idx;
  if (path->alloc < last_str + mctx->max_mb_elem_len + 1)
    {
      re_dfastate_t **new_array;
      Idx old_alloc = path->alloc;
      Idx new_alloc = old_alloc + last_str + mctx->max_mb_elem_len + 1;
      if ((new_alloc < old_alloc)
	  || (SIZE_MAX / sizeof (re_dfastate_t *) < new_alloc))
	return REG_ESPACE;
      new_array = re_realloc (path->array, re_dfastate_t *, new_alloc);
      if (new_array == NULL)
	return REG_ESPACE;
      path->array = new_array;
      path->alloc = new_alloc;
      memset (new_array + old_alloc, '\0',
	      sizeof (re_dfastate_t *) * (path->alloc - old_alloc));
    }

  str_idx = path->next_idx ? path->next_idx : top_str;

  backup_state_log = mctx->state_log;
  backup_cur_idx = mctx->input.cur_idx;
  mctx->state_log = path->array;
  mctx->input.cur_idx = str_idx;

  context = re_string_context_at (&mctx->input, str_idx - 1, mctx->eflags);
  if (str_idx == top_str)
    {
      err = re_node_set_init_1 (&next_nodes, top_node);
      if (err != REG_NOERROR)
	return err;
      err = check_arrival_expand_ecl (dfa, &next_nodes, subexp_num, type);
      if (err != REG_NOERROR)
	{
	  re_node_set_free (&next_nodes);
	  return err;
	}
    }
  else
    {
      cur_state = mctx->state_log[str_idx];
      if (cur_state && cur_state->has_backref)
	{
	  err = re_node_set_init_copy (&next_nodes, &cur_state->nodes);
	  if (err != REG_NOERROR)
	    return err;
	}
      else
	re_node_set_init_empty (&next_nodes);
    }
  if (str_idx == top_str || (cur_state && cur_state->has_backref))
    {
      if (next_nodes.nelem)
	{
	  err = expand_bkref_cache (mctx, &next_nodes, str_idx,
				    subexp_num, type);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&next_nodes);
	      return err;
	    }
	}
      cur_state = re_acquire_state_context (&err, dfa, &next_nodes, context);
      if (cur_state == NULL && err != REG_NOERROR)
	{
	  re_node_set_free (&next_nodes);
	  return err;
	}
      mctx->state_log[str_idx] = cur_state;
    }

  for (null_cnt = 0; str_idx < last_str && null_cnt <= (unsigned int)(mctx->max_mb_elem_len);)
    {
      re_node_set_empty (&next_nodes);
      if (mctx->state_log[str_idx + 1])
	{
	  err = re_node_set_merge (&next_nodes,
				   &mctx->state_log[str_idx + 1]->nodes);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&next_nodes);
	      return err;
	    }
	}
      if (cur_state)
	{
	  err = check_arrival_add_next_nodes (mctx, str_idx,
					      &cur_state->non_eps_nodes,
					      &next_nodes);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&next_nodes);
	      return err;
	    }
	}
      ++str_idx;
      if (next_nodes.nelem)
	{
	  err = check_arrival_expand_ecl (dfa, &next_nodes, subexp_num, type);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&next_nodes);
	      return err;
	    }
	  err = expand_bkref_cache (mctx, &next_nodes, str_idx,
				    subexp_num, type);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&next_nodes);
	      return err;
	    }
	}
      context = re_string_context_at (&mctx->input, str_idx - 1, mctx->eflags);
      cur_state = re_acquire_state_context (&err, dfa, &next_nodes, context);
      if (cur_state == NULL && err != REG_NOERROR)
	{
	  re_node_set_free (&next_nodes);
	  return err;
	}
      mctx->state_log[str_idx] = cur_state;
      null_cnt = cur_state == NULL ? null_cnt + 1 : 0;
    }
  re_node_set_free (&next_nodes);
  cur_nodes = (mctx->state_log[last_str] == NULL ? NULL
	       : &mctx->state_log[last_str]->nodes);
  path->next_idx = str_idx;

  mctx->state_log = backup_state_log;
  mctx->input.cur_idx = backup_cur_idx;

  if (cur_nodes != NULL && re_node_set_contains (cur_nodes, last_node))
    return REG_NOERROR;

  return REG_NOMATCH;
}

static reg_errcode_t
check_arrival_add_next_nodes (re_match_context_t *mctx, Idx str_idx,
			      re_node_set *cur_nodes, re_node_set *next_nodes)
{
  const re_dfa_t *const dfa = mctx->dfa;
  bool ok;
  Idx cur_idx;
  re_node_set union_set;
  re_node_set_init_empty (&union_set);
  for (cur_idx = 0; cur_idx < cur_nodes->nelem; ++cur_idx)
    {
      int naccepted = 0;
      Idx cur_node = cur_nodes->elems[cur_idx];
#ifdef DEBUG
      re_token_type_t type = dfa->nodes[cur_node].type;
      assert (!IS_EPSILON_NODE (type));
#endif
      if (naccepted
	  || check_node_accept (mctx, dfa->nodes + cur_node, str_idx))
	{
	  ok = re_node_set_insert (next_nodes, dfa->nexts[cur_node]);
	  if (! ok)
	    {
	      re_node_set_free (&union_set);
	      return REG_ESPACE;
	    }
	}
    }
  re_node_set_free (&union_set);
  return REG_NOERROR;
}

static reg_errcode_t
check_arrival_expand_ecl (const re_dfa_t *dfa, re_node_set *cur_nodes,
			  Idx ex_subexp, int type)
{
  reg_errcode_t err;
  Idx idx, outside_node;
  re_node_set new_nodes;
#ifdef DEBUG
  assert (cur_nodes->nelem);
#endif
  err = re_node_set_alloc (&new_nodes, cur_nodes->nelem);
  if (err != REG_NOERROR)
    return err;

  for (idx = 0; idx < cur_nodes->nelem; ++idx)
    {
      Idx cur_node = cur_nodes->elems[idx];
      const re_node_set *eclosure = dfa->eclosures + cur_node;
      outside_node = find_subexp_node (dfa, eclosure, ex_subexp, type);
      if (outside_node == REG_MISSING)
	{
	  err = re_node_set_merge (&new_nodes, eclosure);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&new_nodes);
	      return err;
	    }
	}
      else
	{
	  err = check_arrival_expand_ecl_sub (dfa, &new_nodes, cur_node,
					      ex_subexp, type);
	  if (err != REG_NOERROR)
	    {
	      re_node_set_free (&new_nodes);
	      return err;
	    }
	}
    }
  re_node_set_free (cur_nodes);
  *cur_nodes = new_nodes;
  return REG_NOERROR;
}

static reg_errcode_t
check_arrival_expand_ecl_sub (const re_dfa_t *dfa, re_node_set *dst_nodes,
			      Idx target, Idx ex_subexp, int type)
{
  Idx cur_node;
  for (cur_node = target; !re_node_set_contains (dst_nodes, cur_node);)
    {
      bool ok;

      if (dfa->nodes[cur_node].type == type
	  && dfa->nodes[cur_node].opr.idx == ex_subexp)
	{
	  if (type == OP_CLOSE_SUBEXP)
	    {
	      ok = re_node_set_insert (dst_nodes, cur_node);
	      if (! ok)
		return REG_ESPACE;
	    }
	  break;
	}
      ok = re_node_set_insert (dst_nodes, cur_node);
      if (! ok)
	return REG_ESPACE;
      if (dfa->edests[cur_node].nelem == 0)
	break;
      if (dfa->edests[cur_node].nelem == 2)
	{
	  reg_errcode_t err;
	  err = check_arrival_expand_ecl_sub (dfa, dst_nodes,
					      dfa->edests[cur_node].elems[1],
					      ex_subexp, type);
	  if (err != REG_NOERROR)
	    return err;
	}
      cur_node = dfa->edests[cur_node].elems[0];
    }
  return REG_NOERROR;
}

static reg_errcode_t
expand_bkref_cache (re_match_context_t *mctx, re_node_set *cur_nodes,
		    Idx cur_str, Idx subexp_num, int type)
{
  const re_dfa_t *const dfa = mctx->dfa;
  reg_errcode_t err;
  Idx cache_idx_start = search_cur_bkref_entry (mctx, cur_str);
  struct re_backref_cache_entry *ent;

  if (cache_idx_start == REG_MISSING)
    return REG_NOERROR;

 restart:
  ent = mctx->bkref_ents + cache_idx_start;
  do
    {
      Idx to_idx, next_node;

      if (!re_node_set_contains (cur_nodes, ent->node))
	continue;

      to_idx = cur_str + ent->subexp_to - ent->subexp_from;
      if (to_idx == cur_str)
	{
	  re_node_set new_dests;
	  reg_errcode_t err2, err3;
	  next_node = dfa->edests[ent->node].elems[0];
	  if (re_node_set_contains (cur_nodes, next_node))
	    continue;
	  err = re_node_set_init_1 (&new_dests, next_node);
	  err2 = check_arrival_expand_ecl (dfa, &new_dests, subexp_num, type);
	  err3 = re_node_set_merge (cur_nodes, &new_dests);
	  re_node_set_free (&new_dests);
	  if (err != REG_NOERROR || err2 != REG_NOERROR
		  || err3 != REG_NOERROR)
	    {
	      err = (err != REG_NOERROR ? err
		     : (err2 != REG_NOERROR ? err2 : err3));
	      return err;
	    }
	  goto restart;
	}
      else
	{
	  re_node_set union_set;
	  next_node = dfa->nexts[ent->node];
	  if (mctx->state_log[to_idx])
	    {
	      bool ok;
	      if (re_node_set_contains (&mctx->state_log[to_idx]->nodes,
					next_node))
		continue;
	      err = re_node_set_init_copy (&union_set,
					   &mctx->state_log[to_idx]->nodes);
	      ok = re_node_set_insert (&union_set, next_node);
	      if (err != REG_NOERROR || ! ok)
		{
		  re_node_set_free (&union_set);
		  err = err != REG_NOERROR ? err : REG_ESPACE;
		  return err;
		}
	    }
	  else
	    {
	      err = re_node_set_init_1 (&union_set, next_node);
	      if (err != REG_NOERROR)
		return err;
	    }
	  mctx->state_log[to_idx] = re_acquire_state (&err, dfa, &union_set);
	  re_node_set_free (&union_set);
	  if (mctx->state_log[to_idx] == NULL
		  && err != REG_NOERROR)
	    return err;
	}
    }
  while (ent++->more);
  return REG_NOERROR;
}

static bool
build_trtable (const re_dfa_t *dfa, re_dfastate_t *state)
{
  reg_errcode_t err;
  Idx i, j;
  int ch;
  bool need_word_trtable = false;
  bitset_word_t elem, mask;
  bool dests_node_malloced = false;
  bool dest_states_malloced = false;
  Idx ndests;
  re_dfastate_t **trtable;
  re_dfastate_t **dest_states = NULL, **dest_states_word, **dest_states_nl;
  re_node_set follows, *dests_node;
  bitset_t *dests_ch;
  bitset_t acceptable;

  struct dests_alloc
  {
    re_node_set dests_node[SBC_MAX];
    bitset_t dests_ch[SBC_MAX];
  } *dests_alloc;

  if (__libc_use_alloca (sizeof (struct dests_alloc)))
    dests_alloc = (struct dests_alloc *) _alloca (sizeof (struct dests_alloc));
  else
    {
      dests_alloc = re_malloc (struct dests_alloc, 1);
      if (dests_alloc == NULL)
	return false;
      dests_node_malloced = true;
    }
  dests_node = dests_alloc->dests_node;
  dests_ch = dests_alloc->dests_ch;

  state->word_trtable = state->trtable = NULL;

  ndests = group_nodes_into_DFAstates (dfa, state, dests_node, dests_ch);
  if (! REG_VALID_NONZERO_INDEX (ndests))
    {
      if (dests_node_malloced)
	free (dests_alloc);
      if (ndests == 0)
	{
	  state->trtable = (re_dfastate_t **)
	    calloc (sizeof (re_dfastate_t *), SBC_MAX);
	  return true;
	}
      return false;
    }

  err = re_node_set_alloc (&follows, ndests + 1);
  if (err != REG_NOERROR)
    goto out_free;

  if ((((SIZE_MAX - (sizeof (re_node_set) + sizeof (bitset_t)) * SBC_MAX)
	    / (3 * sizeof (re_dfastate_t *)))
	   < ndests))
    goto out_free;

  if (__libc_use_alloca ((sizeof (re_node_set) + sizeof (bitset_t)) * SBC_MAX
			 + ndests * 3 * sizeof (re_dfastate_t *)))
    dest_states = (re_dfastate_t **)
      _alloca (ndests * 3 * sizeof (re_dfastate_t *));
  else
    {
      dest_states = (re_dfastate_t **)
	malloc (ndests * 3 * sizeof (re_dfastate_t *));
      if (dest_states == NULL)
	{
out_free:
	  if (dest_states_malloced)
	    free (dest_states);
	  re_node_set_free (&follows);
	  for (i = 0; i < ndests; ++i)
	    re_node_set_free (dests_node + i);
	  if (dests_node_malloced)
	    free (dests_alloc);
	  return false;
	}
      dest_states_malloced = true;
    }
  dest_states_word = dest_states + ndests;
  dest_states_nl = dest_states_word + ndests;
  bitset_empty (acceptable);

  for (i = 0; i < ndests; ++i)
    {
      Idx next_node;
      re_node_set_empty (&follows);
      for (j = 0; j < dests_node[i].nelem; ++j)
	{
	  next_node = dfa->nexts[dests_node[i].elems[j]];
	  if (next_node != REG_MISSING)
	    {
	      err = re_node_set_merge (&follows, dfa->eclosures + next_node);
	      if (err != REG_NOERROR)
		goto out_free;
	    }
	}
      dest_states[i] = re_acquire_state_context (&err, dfa, &follows, 0);
      if (dest_states[i] == NULL && err != REG_NOERROR)
	goto out_free;
      if (dest_states[i]->has_constraint)
	{
	  dest_states_word[i] = re_acquire_state_context (&err, dfa, &follows,
							  CONTEXT_WORD);
	  if (dest_states_word[i] == NULL && err != REG_NOERROR)
	    goto out_free;

	  if (dest_states[i] != dest_states_word[i] && dfa->mb_cur_max > 1)
	    need_word_trtable = true;

	  dest_states_nl[i] = re_acquire_state_context (&err, dfa, &follows,
							CONTEXT_NEWLINE);
	  if (dest_states_nl[i] == NULL && err != REG_NOERROR)
	    goto out_free;
	}
      else
	{
	  dest_states_word[i] = dest_states[i];
	  dest_states_nl[i] = dest_states[i];
	}
      bitset_merge (acceptable, dests_ch[i]);
    }

  if (!(need_word_trtable))
    {
      trtable = state->trtable =
	(re_dfastate_t **) calloc (sizeof (re_dfastate_t *), SBC_MAX);
      if (trtable == NULL)
	goto out_free;

      for (i = 0; i < BITSET_WORDS; ++i)
	for (ch = i * BITSET_WORD_BITS, elem = acceptable[i], mask = 1;
	     elem;
	     mask <<= 1, elem >>= 1, ++ch)
	  if (elem & 1)
	    {
	      for (j = 0; (dests_ch[j][i] & mask) == 0; ++j)
		;

	      if (dfa->word_char[i] & mask)
		trtable[ch] = dest_states_word[j];
	      else
		trtable[ch] = dest_states[j];
	    }
    }
  else
    {
      trtable = state->word_trtable =
	(re_dfastate_t **) calloc (sizeof (re_dfastate_t *), 2 * SBC_MAX);
      if (trtable == NULL)
	goto out_free;

      for (i = 0; i < BITSET_WORDS; ++i)
	for (ch = i * BITSET_WORD_BITS, elem = acceptable[i], mask = 1;
	     elem;
	     mask <<= 1, elem >>= 1, ++ch)
	  if (elem & 1)
	    {
	      for (j = 0; (dests_ch[j][i] & mask) == 0; ++j)
		;

	      trtable[ch] = dest_states[j];
	      trtable[ch + SBC_MAX] = dest_states_word[j];
	    }
    }

  if (bitset_contain (acceptable, NEWLINE_CHAR))
    {
      for (j = 0; j < ndests; ++j)
	if (bitset_contain (dests_ch[j], NEWLINE_CHAR))
	  {
	    trtable[NEWLINE_CHAR] = dest_states_nl[j];
	    if (need_word_trtable)
	      trtable[NEWLINE_CHAR + SBC_MAX] = dest_states_nl[j];
	    break;
	  }
    }

  if (dest_states_malloced)
    free (dest_states);

  re_node_set_free (&follows);
  for (i = 0; i < ndests; ++i)
    re_node_set_free (dests_node + i);

  if (dests_node_malloced)
    free (dests_alloc);

  return true;
}

static Idx
group_nodes_into_DFAstates (const re_dfa_t *dfa, const re_dfastate_t *state,
			    re_node_set *dests_node, bitset_t *dests_ch)
{
  reg_errcode_t err;
  bool ok;
  Idx i, j, k;
  Idx ndests;
  bitset_t accepts;
  const re_node_set *cur_nodes = &state->nodes;
  bitset_empty (accepts);
  ndests = 0;

  for (i = 0; i < cur_nodes->nelem; ++i)
    {
      re_token_t *node = &dfa->nodes[cur_nodes->elems[i]];
      re_token_type_t type = node->type;
      unsigned int constraint = node->constraint;

      if (type == CHARACTER)
	bitset_set (accepts, node->opr.c);
      else if (type == SIMPLE_BRACKET)
	{
	  bitset_merge (accepts, node->opr.sbcset);
	}
      else if (type == OP_PERIOD)
	{
	    bitset_set_all (accepts);
	  if (!(dfa->syntax & RE_DOT_NEWLINE))
	    bitset_clear (accepts, '\n');
	  if (dfa->syntax & RE_DOT_NOT_NULL)
	    bitset_clear (accepts, '\0');
	}
      else
	continue;

      if (constraint)
	{
	  if (constraint & NEXT_NEWLINE_CONSTRAINT)
	    {
	      bool accepts_newline = bitset_contain (accepts, NEWLINE_CHAR);
	      bitset_empty (accepts);
	      if (accepts_newline)
		bitset_set (accepts, NEWLINE_CHAR);
	      else
		continue;
	    }
	  if (constraint & NEXT_ENDBUF_CONSTRAINT)
	    {
	      bitset_empty (accepts);
	      continue;
	    }

	  if (constraint & NEXT_WORD_CONSTRAINT)
	    {
	      bitset_word_t any_set = 0;
	      if (type == CHARACTER && !node->word_char)
		{
		  bitset_empty (accepts);
		  continue;
		}
		for (j = 0; j < BITSET_WORDS; ++j)
		  any_set |= (accepts[j] &= dfa->word_char[j]);
	      if (!any_set)
		continue;
	    }
	  if (constraint & NEXT_NOTWORD_CONSTRAINT)
	    {
	      bitset_word_t any_set = 0;
	      if (type == CHARACTER && node->word_char)
		{
		  bitset_empty (accepts);
		  continue;
		}
		for (j = 0; j < BITSET_WORDS; ++j)
		  any_set |= (accepts[j] &= ~dfa->word_char[j]);
	      if (!any_set)
		continue;
	    }
	}

      for (j = 0; j < ndests; ++j)
	{
	  bitset_t intersec;
	  bitset_t remains;
	  bitset_word_t has_intersec, not_subset, not_consumed;

	  if (type == CHARACTER && !bitset_contain (dests_ch[j], node->opr.c))
	    continue;

	  has_intersec = 0;
	  for (k = 0; k < BITSET_WORDS; ++k)
	    has_intersec |= intersec[k] = accepts[k] & dests_ch[j][k];
	  if (!has_intersec)
	    continue;

	  not_subset = not_consumed = 0;
	  for (k = 0; k < BITSET_WORDS; ++k)
	    {
	      not_subset |= remains[k] = ~accepts[k] & dests_ch[j][k];
	      not_consumed |= accepts[k] = accepts[k] & ~dests_ch[j][k];
	    }

	  if (not_subset)
	    {
	      bitset_copy (dests_ch[ndests], remains);
	      bitset_copy (dests_ch[j], intersec);
	      err = re_node_set_init_copy (dests_node + ndests, &dests_node[j]);
	      if (err != REG_NOERROR)
		goto error_return;
	      ++ndests;
	    }

	  ok = re_node_set_insert (&dests_node[j], cur_nodes->elems[i]);
	  if (! ok)
	    goto error_return;

	  if (!not_consumed)
	    break;
	}
      if (j == ndests)
	{
	  bitset_copy (dests_ch[ndests], accepts);
	  err = re_node_set_init_1 (dests_node + ndests, cur_nodes->elems[i]);
	  if (err != REG_NOERROR)
	    goto error_return;
	  ++ndests;
	  bitset_empty (accepts);
	}
    }
  return ndests;
 error_return:
  for (j = 0; j < ndests; ++j)
    re_node_set_free (dests_node + j);
  return REG_MISSING;
}

static bool
check_node_accept (const re_match_context_t *mctx, const re_token_t *node,
		   Idx idx)
{
  unsigned char ch;
  ch = re_string_byte_at (&mctx->input, idx);
  switch (node->type)
    {
    case CHARACTER:
      if (node->opr.c != ch)
        return false;
      break;

    case SIMPLE_BRACKET:
      if (!bitset_contain (node->opr.sbcset, ch))
        return false;
      break;

    case OP_PERIOD:
      if ((ch == '\n' && !(mctx->dfa->syntax & RE_DOT_NEWLINE))
	  || (ch == '\0' && (mctx->dfa->syntax & RE_DOT_NOT_NULL)))
	return false;
      break;

    default:
      return false;
    }

  if (node->constraint)
    {
      unsigned int context = re_string_context_at (&mctx->input, idx,
						   mctx->eflags);
      if (NOT_SATISFY_NEXT_CONSTRAINT (node->constraint, context))
	return false;
    }

  return true;
}

static reg_errcode_t
extend_buffers (re_match_context_t *mctx)
{
  reg_errcode_t ret;
  re_string_t *pstr = &mctx->input;

  if (SIZE_MAX / 2 / sizeof (re_dfastate_t *) <= pstr->bufs_len)
    return REG_ESPACE;

  ret = re_string_realloc_buffers (pstr, pstr->bufs_len * 2);
  if (ret != REG_NOERROR)
    return ret;

  if (mctx->state_log != NULL)
    {
      re_dfastate_t **new_array = re_realloc (mctx->state_log, re_dfastate_t *,
					      pstr->bufs_len + 1);
      if (new_array == NULL)
	return REG_ESPACE;
      mctx->state_log = new_array;
    }

  if (pstr->icase)
    {
	build_upper_buffer (pstr);
    }
  else
    {
	{
	  if (pstr->trans != NULL)
	    re_string_translate_buffer (pstr);
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
match_ctx_init (re_match_context_t *mctx, int eflags, Idx n)
{
  mctx->eflags = eflags;
  mctx->match_last = REG_MISSING;
  if (n > 0)
    {
      size_t max_object_size =
	MAX (sizeof (struct re_backref_cache_entry),
	     sizeof (re_sub_match_top_t *));
      if (SIZE_MAX / max_object_size < n)
	return REG_ESPACE;

      mctx->bkref_ents = re_malloc (struct re_backref_cache_entry, n);
      mctx->sub_tops = re_malloc (re_sub_match_top_t *, n);
      if (mctx->bkref_ents == NULL || mctx->sub_tops == NULL)
	return REG_ESPACE;
    }
  mctx->abkref_ents = n;
  mctx->max_mb_elem_len = 1;
  mctx->asub_tops = n;
  return REG_NOERROR;
}

static void
match_ctx_clean (re_match_context_t *mctx)
{
  Idx st_idx;
  for (st_idx = 0; st_idx < mctx->nsub_tops; ++st_idx)
    {
      Idx sl_idx;
      re_sub_match_top_t *top = mctx->sub_tops[st_idx];
      for (sl_idx = 0; sl_idx < top->nlasts; ++sl_idx)
	{
	  re_sub_match_last_t *last = top->lasts[sl_idx];
	  re_free (last->path.array);
	  re_free (last);
	}
      re_free (top->lasts);
      if (top->path)
	{
	  re_free (top->path->array);
	  re_free (top->path);
	}
      free (top);
    }

  mctx->nsub_tops = 0;
  mctx->nbkref_ents = 0;
}

static void
match_ctx_free (re_match_context_t *mctx)
{
  match_ctx_clean (mctx);
  re_free (mctx->sub_tops);
  re_free (mctx->bkref_ents);
}

static reg_errcode_t
match_ctx_add_entry (re_match_context_t *mctx, Idx node, Idx str_idx, Idx from,
		     Idx to)
{
  if (mctx->nbkref_ents >= mctx->abkref_ents)
    {
      struct re_backref_cache_entry* new_entry;
      new_entry = re_realloc (mctx->bkref_ents, struct re_backref_cache_entry,
			      mctx->abkref_ents * 2);
      if (new_entry == NULL)
	{
	  re_free (mctx->bkref_ents);
	  return REG_ESPACE;
	}
      mctx->bkref_ents = new_entry;
      memset (mctx->bkref_ents + mctx->nbkref_ents, '\0',
	      sizeof (struct re_backref_cache_entry) * mctx->abkref_ents);
      mctx->abkref_ents *= 2;
    }
  if (mctx->nbkref_ents > 0
      && mctx->bkref_ents[mctx->nbkref_ents - 1].str_idx == str_idx)
    mctx->bkref_ents[mctx->nbkref_ents - 1].more = 1;

  mctx->bkref_ents[mctx->nbkref_ents].node = node;
  mctx->bkref_ents[mctx->nbkref_ents].str_idx = str_idx;
  mctx->bkref_ents[mctx->nbkref_ents].subexp_from = from;
  mctx->bkref_ents[mctx->nbkref_ents].subexp_to = to;

  mctx->bkref_ents[mctx->nbkref_ents].eps_reachable_subexps_map
    = (from == to ? -1 : 0);

  mctx->bkref_ents[mctx->nbkref_ents++].more = 0;
  if ((unsigned int)(mctx->max_mb_elem_len) < to - from)
    mctx->max_mb_elem_len = to - from;
  return REG_NOERROR;
}

static Idx
search_cur_bkref_entry (const re_match_context_t *mctx, Idx str_idx)
{
  Idx left, right, mid, last;
  last = right = mctx->nbkref_ents;
  for (left = 0; left < right;)
    {
      mid = (left + right) / 2;
      if (mctx->bkref_ents[mid].str_idx < str_idx)
	left = mid + 1;
      else
	right = mid;
    }
  if (left < last && mctx->bkref_ents[left].str_idx == str_idx)
    return left;
  else
    return REG_MISSING;
}

static reg_errcode_t
match_ctx_add_subtop (re_match_context_t *mctx, Idx node, Idx str_idx)
{
#ifdef DEBUG
  assert (mctx->sub_tops != NULL);
  assert (mctx->asub_tops > 0);
#endif
  if (mctx->nsub_tops == mctx->asub_tops)
    {
      Idx new_asub_tops = mctx->asub_tops * 2;
      re_sub_match_top_t **new_array = re_realloc (mctx->sub_tops,
						   re_sub_match_top_t *,
						   new_asub_tops);
      if (new_array == NULL)
	return REG_ESPACE;
      mctx->sub_tops = new_array;
      mctx->asub_tops = new_asub_tops;
    }
  mctx->sub_tops[mctx->nsub_tops] = calloc (1, sizeof (re_sub_match_top_t));
  if (mctx->sub_tops[mctx->nsub_tops] == NULL)
    return REG_ESPACE;
  mctx->sub_tops[mctx->nsub_tops]->node = node;
  mctx->sub_tops[mctx->nsub_tops++]->str_idx = str_idx;
  return REG_NOERROR;
}

static re_sub_match_last_t *
match_ctx_add_sublast (re_sub_match_top_t *subtop, Idx node, Idx str_idx)
{
  re_sub_match_last_t *new_entry;
  if (subtop->nlasts == subtop->alasts)
    {
      Idx new_alasts = 2 * subtop->alasts + 1;
      re_sub_match_last_t **new_array = re_realloc (subtop->lasts,
						    re_sub_match_last_t *,
						    new_alasts);
      if (new_array == NULL)
	return NULL;
      subtop->lasts = new_array;
      subtop->alasts = new_alasts;
    }
  new_entry = calloc (1, sizeof (re_sub_match_last_t));
  if (new_entry != NULL)
    {
      subtop->lasts[subtop->nlasts] = new_entry;
      new_entry->node = node;
      new_entry->str_idx = str_idx;
      ++subtop->nlasts;
    }
  return new_entry;
}

static void
sift_ctx_init (re_sift_context_t *sctx, re_dfastate_t **sifted_sts,
	       re_dfastate_t **limited_sts, Idx last_node, Idx last_str_idx)
{
  sctx->sifted_states = sifted_sts;
  sctx->limited_states = limited_sts;
  sctx->last_node = last_node;
  sctx->last_str_idx = last_str_idx;
  re_node_set_init_empty (&sctx->limits);
}
