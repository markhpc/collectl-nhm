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
          unless (!defined($data) || $data eq "")
          {
            dataAnalyzeProcesses($type, $data, substr($type, 5), 0);
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
