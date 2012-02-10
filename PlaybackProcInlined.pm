use IO::Zlib;

sub playback {
  # Build the array of subsys type regexs and analyzers to call  
  my $subsysArray = buildSubsysArray($subsys);
  my $subsysHash = buildSubsysHash($subsys);

  if ($zInFlag)
  {
    tie *PLAY, 'IO::Zlib', $file, "rb";
  }
  else
  {
    open PLAY, "<$file" or logmsg("F", "Couldn't open '$file'");
  }

  # Create some booleans to use in the loop 
  my $skipGrep = ($grepPattern eq '') ? 1 : 0;
  my $debug4 = $debug & 4;
  my $debug32 = $debug & 32;

  # Doncha love special cases?  Turns out when reading back process data
  # from a PRC file which was created from multiple logs, if a process from
  # one log comes up with the same pid as that of an earlier log, there's
  # no easy way to tell.  Now there is!
  writeInterFileMarker() if $prcFileCount>1 && $filename ne '';

  LINE: while ($line = <PLAY>)
  {
    print $line if $debug4;

    unless ($skipGrep || $skip)
    {
      if ($line=~/$grepPattern/)
      {
        my $msec=(split(/\./, $newSeconds[$rawPFlag]))[1];
        my ($ss, $mm, $hh, $mday, $mon, $year)=localtime($newSeconds[$rawPFlag]);
        $datetime=sprintf("%02d:%02d:%02d", $hh, $mm, $ss);
        $datetime=sprintf("%02d/%02d %s", $mon+1, $mday, $datetime)                   if $options=~/d/;
        $datetime=sprintf("%04d%02d%02d %s", $year+1900, $mon+1, $mday, $datetime)    if $options=~/D/;
        $datetime.=".$msec"                                                           if ($options=~/m/);
        print "$datetime $line";
      }
      next LINE;
    }

    # Only for debugging and typically used with -d4, we want to see the /proc
    # fields as they're read but NOT process them
    unless ($debug32 || $skip)
    {
      # Custom data analysis based on KEY which must be defined in custom module
      if ($impNumMods > 0)
      {
        chomp $line;
        ($type, $data)=split(/\s+/, $line, 2);
        unless (!defined($data) || $data eq "")
        {
          for (my $i=0; $i<$impNumMods; $i++)
          {
            &{$impAnalyze[$i]}($type, \$data)    if $type=~/$impKey[$i]/;
          }
        }
      }

      # For speed we match common lines and throw them away if the
      # associated subsystem wasn't requested.
      if (substr($line, 0, 5) eq "proc:")
      {
        if (exists $subsysHash->{Z})
        {
          chomp $line;
          ($type, $data)=split(/\s+/, $line, 2);
#          my $procPidNow = substr($line, 5, 5);
#          my $data = substr($line, 11);
          unless (!defined($data) || $data eq "")
          {
            my $procPidNow = substr($type, 5);
            unless (defined $procIndexes{$procPidNow})
            {
              # make sure we note this this interval has process data in it and is ready
              # to be reported.
              $interval2Print=1;

              my $i=$procIndexes{$procPidNow}=nextAvailProcIndex();
              $procMinFltLast[$i] = $procMajFltLast[$i] = $procUTimeLast[$i]  =
              $procSTimeLast[$i]  = $procCUTimeLast[$i] = $procCSTimeLast[$i] =
              $procRCharLast[$i]  = $procWCharLast[$i]  = $procSyscrLast[$i]  =
              $procSyscwLast[$i]  = $procRBytesLast[$i] = $procWBytesLast[$i] =
              $procCancelLast[$i] = 0;

              # FIXME: Oddly, zombie processes seem to be getting reset here.  For now 
              # we check if procVmSize is defined to replicate the stock collectl
              # behavior.
              unless (defined $procVmSize[$i]) {
                $procVmSize[$i] = $procVmLck[$i] = $procVmRSS[$i] = $procVmData[$i] =
                $procVmStk[$i] = $procVmExe[$i] = $procVmLib[$i] = 0;
              }

              print "### new index $i allocated for $procPidNow\n"    if $debug & 256;

              # note - %procSeen works just like %pidSeen, except to keep collection
              # and formatting separate, we need to keep these flags separate too,
              # expecially since in playback mode %pidSeen never gets set.
              #    $procSeen{$procPidNow}=1;
            }
            $procSeen{$procPidNow}=1;
            my $i=$procIndexes{$procPidNow};
 
            if (substr($data, 0, 2) eq 'io')
            {
              if (substr($data, 3, 2) eq "rc")
              {
                $procRChar= int substr($data, 10);
                next LINE;
              }
              if (substr($data, 3, 2) eq "wc")
              {
                $procWChar= int substr($data, 10);
                next LINE;
              }
              if (substr($data, 3, 2)  eq "re")
              {
                $procRBytes= int substr($data, 15);
                next LINE;
              }
              if (substr($data, 3, 2) eq "wr") 
              {
                $procWBytes= int substr($data, 16);
                next LINE;
              }
              if (substr($data, 3, 5) eq "syscr")
              {
                $procSyscr= int substr($data, 10);
                next LINE;
              }
              if (substr($data, 3, 5) eq "syscw")
              {
                $procSyscw= int substr($data, 10);
                next LINE;
              }
              if (substr($data, 3, 2) eq 'ca')
              {
                # CentOS V4 (and therefore must be true for some RHEL distros) 
                # doesn't include all counters so if one isn't set I'm going
                # to assume ALL aren't set
                $procRChar=$procWChar=$procSyscr=$procSyscw=0 unless defined($procRChar);

                $procCancel= int substr($data, 26);

                $procRKBC[$i]=$procRChar-$procRCharLast[$i];
                $procRKBC[$i]=$procRKBC[$i] < 0 ? fix($procRKBC[$i])/1024 : $procRKBC[$i]/1024;
                $procRCharLast[$i]=$procRChar;

                $procWKBC[$i]=$procWChar-$procWCharLast[$i];
                $procWKBC[$i]=$procWKBC[$i] < 0 ? fix($procWKBC[$i])/1024 : $procWKBC[$i]/1024;
                $procWCharLast[$i]=$procWChar;

                $procRSys[$i]=$procSyscr-$procSyscrLast[$i];
                $procRSys[$i]=fix($procRSys[$i]) if ($procRSys[$i] < 0);
                $procSyscrLast[$i]=$procSyscr;

                $procWSys[$i]=$procSyscw-$procSyscwLast[$i];
                $procWSys[$i]=fix($procWsys[$i]) if ($procWSys[$i] < 0);
                $procSyscwLast[$i]=$procSyscw;

                $procRKB[$i]=$procRBytes-$procRBytesLast[$i];
                $procRKB[$i]=$procRKB[$i] < 0 ? fix($procRKB[$i])/1024 : $procRKB[$i]/1024;
                $procRBytesLast[$i]=$procRBytes;

                $procWKB[$i]=$procWBytes-$procWBytesLast[$i];
                $procWKB[$i]=$procWKB[$i] < 0 ? fix($procWKB[$i])/1024 : $procWKB[$i]/1024;
                $procWBytesLast[$i]=$procWBytes;

                $procCKB[$i]=$procCancel-$procCancelLast[$i];
                $procCKB[$i]=$procCKB[$i] < 0 ? fix($procCKB[$i])/1024 : $procCKB[$i]/1024;
                $procCancelLast[$i]=$procCancel;

                next LINE;
              }
              next LINE;
            }
            if (substr($data, 0, 5) eq 'stat ')
            {
              # 'C' variables include the values for dead children
              # Note that incomplete records happen too often to bother logging
              $procPid[$i]= $procPidNow;  # don't need to pull out of string...
              $procThread[$i]=0;
              ($procName[$i], $procState[$i], $procPpid[$i],
               $procMinFltTot[$i], $procMajFltTot[$i],
               $procUTimeTot[$i], $procSTimeTot[$i],
               $procCUTimeTot[$i], $procCSTimeTot[$i], $procPri[$i], $procNice[$i], $procCPU[$i])=
                          (split(/\s/, $data))[2,3,4,10,12,14,15,16,17,18,19,39];
              next LINE    if !defined($procSTimeTot[$i]);  # check for incomplete

              if ($procOpts=~/c/)
              {
                $procUTimeTot[$i]+=$procCUTimeTot[$i];
                $procSTimeTot[$i]+=$procCSTimeTot[$i];
              }

              $procName[$i] = substr($procName[$i], 1, -1) if (substr($procName[$i], 0, 1) eq "(");
              $procPri[$i]='RT' if $procPri[$i]<0;

              $procMinFlt[$i]=$procMinFltTot[$i]-$procMinFltLast[$i];
              $procMinFlt[$i]=fix($procMinFlt[$i]) if ($procMinFlt[$i] < 0);
              $procMinFltLast[$i]=$procMinFltTot[$i];

              $procMajFlt[$i]=$procMajFltTot[$i]-$procMajFltLast[$i];
              $procMajFlt[$i]=fix($procMajFlt[$i]) if ($procMajFlt[$i] < 0);
              $procMajFltLast[$i]=$procMajFltTot[$i];

              $procUTime[$i]=$procUTimeTot[$i]-$procUTimeLast[$i];
              $procUTime[$i]=fix($procUTimeTot[$i]) if ($procUTimeTot[$i] < 0);
              $procUTimeLast[$i]= $procUTimeTot[$i];

              $procSTime[$i]=$procSTimeTot[$i]-$procSTimeLast[$i];
              $procSTime[$i]=fix($procSTimeTot[$i]) if ($procSTimeTot[$i] < 0);
              $procSTimeLast[$i]= $procSTimeTot[$i];
              next LINE;
            }

            # if bad stat file skip the rest
            next LINE unless defined($procSTimeTot[$i]);
            if (substr($data, 0, 2) eq 'Vm')
            {
              my ($procType, $value) = unpack('A6x2A8', $data);
              next LINE if ($procType eq 'VmPeak' and $procVmPeak[$i]= int $value);
              next LINE if ($procType eq 'VmSize' and $procVmSize[$i]= int $value);
              next LINE if ($procType eq  'VmLck:' and $procVmLck[$i]= int $value);
              next LINE if ($procType eq  'VmHWM:' and $procVmHWM[$i]= int $value);
              next LINE if ($procType eq  'VmRSS:' and $procVmRSS[$i]= int $value);
              next LINE if ($procType eq 'VmData' and $procVmData[$i]= int $value);
              next LINE if ($procType eq  'VmStk:' and $procVmStk[$i]= int $value);
              next LINE if ($procType eq  'VmExe:' and $procVmExe[$i]= int $value);
              next LINE if ($procType eq  'VmLib:' and $procVmLib[$i]= int $value);
              next LINE if ($procType eq  'VmPTE:' and $procVmPTE[$i]= int $value);
            }
            next LINE if (substr($data, 0, 3) eq "cmd" and $procCmd[$i]=substr($data, 4));
            next LINE if (substr($data, 0, 2) eq "Tg" and $procTgid[$i]=substr($data, 7));
            if (substr($data, 0, 2) eq "Ui")
            {
              $uid=(split(/\t/, $data))[1];
              $procUser[$i]=(defined($UidSelector{$uid})) ? $UidSelector{$uid} : $uid;
            }
          }
        }
        next LINE;
      }
      if (substr($line, 0, 5) eq "procT")
      {
        if (exists $subsysHash->{Z})
        {
          chomp $line;
          ($type, $data)=split(/\s+/, $line, 2);
          unless (!defined($data) || $data eq "")
          {
            dataAnalyzeProcesses($type, $data, substr($type, 6), 1);
          }
        }
        next LINE;
      }
      if (substr($line, 0, 5) eq "Slab ")
      {
        if (exists $subsysHash->{yi})
        {
          chomp $line;
          ($type, $data)=split(/\s+/, $line, 2);
          unless (!defined($data) || $data eq "")
          {
            dataAnalyzeSlabs($type, $data);
          }
        }
        next LINE;
      }
      if (substr($line, 0, 4) eq 'int ')
      {
        if (exists $subsysHash->{ji})
        {
          chomp $line;
          ($type, $data)=split(/\s+/, $line, 2);
          unless (!defined($data) || $data eq "")
          {
            dataAnalyzeInterrupts($type, $data);
          }
        }
        next LINE;
      }

      # Next we iterate over the other subsystems.
      foreach my $subsys (@$subsysArray)
      {
        if (substr($line, $subsys->[1], $subsys->[2]) eq $subsys->[0])
        {
          if (exists $subsys->[3])
          {
            chomp $line;
            ($type, $data)=split(/\s+/, $line, 2);
            unless (!defined($data) || $data eq "")
            {
              $subsys->[3]->($type, $data);
            }
          }
          next LINE;
        }
      }
    }
    next unless (substr($line, 0, 3) eq ">>>");
    # if new interval, it really indicates the end of the last one but its
    # time is that of the new one so process last interval before saving.
    # if this isn't a valid interval marker the file somehow got corrupted
    # which was seen one time before flush error handling was put in.  Don't
    # if that was the problem or not so we'll keep this extra test.

    # we need to make sure both $lastSeconds and $newSeconds track BOTH the
    # raw and rawp files, if both exist.

    $timestampFlag=1;
    if ($line!~/^>>> (\d+\.\d+) <<</)
    {
      logmsg("E", "Corrupted file do to invalid time marker in '$file'\n".
                    "Ignoring the rest of file.  Last valid marker: $newSeconds[$rawPFlag]");
      next;
    }

    # At this point and if defined $newSeconds is actually pointing to the last interval
    # and be sure to convert to local time so --from/--thru checks work.
    my $thisSeconds=$1+$timeAdjust;
    $lastSeconds[$rawPFlag]=(defined($newSeconds[$rawPFlag])) ? $newSeconds[$rawPFlag] : 0;
    $skip=0    if $fromSecs && $thisSeconds>=$fromSecs;
    last       if $thruSecs && $lastSeconds[$rawPFlag]>$thruSecs;

    $timestampCounter[$rawPFlag]++    if !$skip;
    if ($timestampCounter[$rawPFlag]==1)
    {
        # If a second (or more) file for same host, are their timstamps consecutive?
        # Since we could have a raw/rawp file the way to tell a new file is that
        # $newSeconds will be defined.
        # If NOT consecutive (or first file for a host), init 'last' variables, noting
        # we also need to init if there was a disk configuration change.
      $consecutiveFlag=(!$newPrefixFlag && defined($newSeconds[$rawPFlag]) && $thisSeconds==$newSeconds[$rawPFlag] && !$diskChangeFlag) ? 1 : 0;
      $newSeconds[$rawPFlag]=$thisSeconds;
      if (!$consecutiveFlag)
      {
        # if not doing raw/rawp files, init everything, otherwise just init the type we're doing
        initLast()             if ($playback{$prefix}->{flags} & 1)==0;
        initLast($rawPFlag)    if  $playback{$prefix}->{flags} & 1;
        $lastSecs[$rawPFlag]=$thisSeconds;
      }
      print "ConsecFlag: $consecutiveFlag\n"    if $debug & 1;
      next;
    }
    $newSeconds[$rawPFlag]=$fullTime=$thisSeconds;    # we use '$fullTime' for $microInterval re-calculation

    # track from/thru times for each file to be used for -oA in terminal mode
    if (!$skip && !$rawPFlag)
    {
      $fileFrom=$newSeconds[$rawPFlag]    if !defined($fileFrom);
      $fileThru=$newSeconds[$rawPFlag];
    }

    # Either we're processing a timestamp marker OR data entries
    # When using a single raw file that has inteval markers for all record and newer rawp
    # files that only have them for interval2 only we need to force the 'print' flag each time
    $interval2Print=1    if $rawPFlag && $recVersion ge '3.3.5';

    # We already skipped first interval marker.  As for the second one, which indicates the end of
    # a complete set of data, we only process that if we have consecutive files in which case
    # we get to use the last file's data for the previous interval's data.  BUT we have to make
    # sure 'initInterval' called for second interval which may have been skipped.
    my $saveI2P=$interval2Print;    # gets reset to 0 during intervalEnd()
    intervalEnd($lastSeconds[$rawPFlag])    if $consecutiveFlag || $timestampCounter[$rawPFlag]>2;
    initInterval()    if $timestampCounter[$rawPFlag]==2;
    $firstTime2=0     if $saveI2P;
    $firstTime=0;

    # Reset the timestampFlag unless we are at the end of the file.
    $timestampFlag = 0 unless eof;
  }
  close PLAY;
}

1;
