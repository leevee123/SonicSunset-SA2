# Original model setup: selected generated pseudocode

Generated C is unreviewed; full original artifacts and hashes are in source-artifacts.csv. Large quantization expansions are filtered and require original words.

### 0x800ed368 (670 lines; filtered)

```c
void FUN_800ed368(float *param_1,float *param_2,float *param_3)
  if (bVar3 == 4 || bVar3 == 6) {
    dVar7 = (double)(lVar5 * (longlong)(double)*(char *)param_1);
    if (false) {
      dVar22 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_1 + 1));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar7 = (double)(lVar5 * (longlong)(double)*(short *)param_1);
    if (false) {
      dVar22 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_1 + 2));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar13 = (double)(lVar5 * (longlong)(double)*(char *)param_2);
    if (false) {
      dVar28 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 1));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar13 = (double)(lVar5 * (longlong)(double)*(short *)param_2);
    if (false) {
      dVar28 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_2 + 2));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar14 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar29 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 9));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar14 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar29 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_2 + 10));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar15 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar30 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 0x11));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar15 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar30 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_2 + 0x12));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar9 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar24 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_1 + 0x11));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar9 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar24 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_1 + 0x12));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar21 = (double)(lVar5 * (longlong)(double)DAT_803ad5c8._0_1_);
    if (false) {
      dVar36 = (double)(lVar5 * (longlong)(double)DAT_803ad5c8._1_1_);
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar21 = (double)(lVar5 * (longlong)(double)DAT_803ad5c8._0_2_);
    if (false) {
      dVar36 = (double)(lVar5 * (longlong)(double)DAT_803ad5c8._2_2_);
    dVar21 = (double)DAT_803ad5c8;
    if (false) {
      dVar36 = (double)DAT_803ad5cc;
  if (bVar3 == 4 || bVar3 == 6) {
    dVar16 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar31 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 0x19));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar16 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar31 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_2 + 0x1a));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar8 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar23 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_1 + 9));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar8 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar23 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_1 + 10));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar10 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar25 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_1 + 0x19));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar10 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar25 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_1 + 0x1a));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar17 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar32 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 0x21));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar17 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
      dVar32 = (double)(lVar5 * (longlong)(double)*(short *)((int)param_2 + 0x22));
    if (false) {
  if (bVar3 == 4 || bVar3 == 6) {
    dVar18 = (double)(lVar5 * (longlong)(double)*(char *)pfVar1);
    if (false) {
      dVar33 = (double)(lVar5 * (longlong)(double)*(char *)((int)param_2 + 0x29));
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar18 = (double)(lVar5 * (longlong)(double)*(short *)pfVar1);
    if (false) {
```

### 0x800ed798 (82 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x800ed798; retail_virtual; canonical original-file offset 0xea798. This is not original source or a verified behavior reconstruction. */


void FUN_800ed798(double param_1,double param_2,double param_3,undefined4 *param_4)

{
  float *pfVar1;
  byte bVar2;
  byte bVar3;
  double dVar4;
  undefined4 uVar5;
  float fVar6;
  uint unaff_GQR0;
  double dVar7;
  
  fVar6 = DAT_803b07cc;
  uVar5 = DAT_803b07c8;
  dVar7 = (double)DAT_803b07cc;
  param_4[3] = (float)param_1;
  param_4[7] = (float)param_2;
  pfVar1 = (float *)(param_4 + 1);
  bVar2 = (byte)unaff_GQR0 & 7;
  bVar3 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    *(char *)pfVar1 = (char)(dVar4 * dVar7);
    if (true) {
      *(char *)((int)param_4 + 5) = (char)(dVar4 * dVar7);
    }
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    *(short *)pfVar1 = (short)(dVar4 * dVar7);
    if (true) {
      *(short *)((int)param_4 + 6) = (short)(dVar4 * dVar7);
    }
  }
  else {
    *pfVar1 = fVar6;
    if (true) {
      param_4[2] = fVar6;
    }
  }
  pfVar1 = (float *)(param_4 + 8);
  bVar2 = (byte)unaff_GQR0 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    *(char *)pfVar1 = (char)(dVar4 * dVar7);
    if (true) {
      *(char *)((int)param_4 + 0x21) = (char)(dVar4 * dVar7);
    }
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    *(short *)pfVar1 = (short)(dVar4 * dVar7);
    if (true) {
      *(short *)((int)param_4 + 0x22) = (short)(dVar4 * dVar7);
    }
  }
  else {
    *pfVar1 = fVar6;
    if (true) {
      param_4[9] = fVar6;
    }
  }
  param_4[4] = fVar6;
  param_4[5] = uVar5;
  param_4[6] = fVar6;
  param_4[10] = uVar5;
  param_4[0xb] = (float)param_3;
  *param_4 = uVar5;
  return;
}

```

### 0x800ed7cc (130 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x800ed7cc; retail_virtual; canonical original-file offset 0xea7cc. This is not original source or a verified behavior reconstruction. */


void FUN_800ed7cc(double param_1,double param_2,double param_3,float *param_4)

{
  float *pfVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  double dVar5;
  float fVar6;
  uint unaff_GQR0;
  double dVar7;
  
  fVar6 = DAT_803b07cc;
  dVar7 = (double)DAT_803b07cc;
  *param_4 = (float)param_1;
  pfVar1 = param_4 + 1;
  bVar2 = (byte)unaff_GQR0;
  bVar3 = bVar2 & 7;
  bVar4 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar5 = 1.0;
  }
  else {
    dVar5 = (double)ldexpf(bVar4 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar1 = (char)(dVar5 * dVar7);
    if (true) {
      *(char *)((int)param_4 + 5) = (char)(dVar5 * dVar7);
    }
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar1 = (short)(dVar5 * dVar7);
    if (true) {
      *(short *)((int)param_4 + 6) = (short)(dVar5 * dVar7);
    }
  }
  else {
    *pfVar1 = fVar6;
    if (true) {
      param_4[2] = fVar6;
    }
  }
  pfVar1 = param_4 + 3;
  bVar3 = bVar2 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar5 = 1.0;
  }
  else {
    dVar5 = (double)ldexpf(bVar4 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar1 = (char)(dVar5 * dVar7);
    if (true) {
      *(char *)((int)param_4 + 0xd) = (char)(dVar5 * dVar7);
    }
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar1 = (short)(dVar5 * dVar7);
    if (true) {
      *(short *)((int)param_4 + 0xe) = (short)(dVar5 * dVar7);
    }
  }
  else {
    *pfVar1 = fVar6;
    if (true) {
      param_4[4] = fVar6;
    }
  }
  param_4[5] = (float)param_2;
  pfVar1 = param_4 + 6;
  bVar3 = bVar2 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar5 = 1.0;
  }
  else {
    dVar5 = (double)ldexpf(bVar4 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar1 = (char)(dVar5 * dVar7);
    if (true) {
      *(char *)((int)param_4 + 0x19) = (char)(dVar5 * dVar7);
    }
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar1 = (short)(dVar5 * dVar7);
    if (true) {
      *(short *)((int)param_4 + 0x1a) = (short)(dVar5 * dVar7);
    }
  }
  else {
    *pfVar1 = fVar6;
    if (true) {
      param_4[7] = fVar6;
    }
  }
  pfVar1 = param_4 + 8;
```

### 0x80100d44 (86 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x80100d44; retail_virtual; canonical original-file offset 0xfdd44. This is not original source or a verified behavior reconstruction. */


void FUN_80100d44(uint param_1,undefined4 param_2,uint param_3,int param_4,uint param_5)

{
  uint *puVar1;
  uint *puVar2;
  uint *puVar3;
  
  puVar1 = (uint *)(PTR_DAT_803ad640 + param_1 * 4 + 0x1c);
  puVar2 = (uint *)(PTR_DAT_803ad640 + param_1 * 4 + 0x3c);
  puVar3 = (uint *)(PTR_DAT_803ad640 + param_1 * 4 + 0x5c);
  if (true) {
    switch(param_2) {
    case 9:
      *puVar1 = *puVar1 & 0xfffffffe | param_3;
      *puVar1 = *puVar1 & 0xfffffff1 | param_4 << 1;
      *puVar1 = *puVar1 & 0xfffffe0f | (param_5 & 0xff) << 4;
      break;
    case 10:
    case 0x19:
      *puVar1 = *puVar1 & 0xffffe3ff | param_4 << 10;
      if (param_3 == 2) {
        *puVar1 = *puVar1 & 0xfffffdff | 0x200;
        *puVar1 = *puVar1 & 0x7fffffff | 0x80000000;
      }
      else {
        *puVar1 = *puVar1 & 0xfffffdff | param_3 << 9;
        *puVar1 = *puVar1 & 0x7fffffff;
      }
      break;
    case 0xb:
      *puVar1 = *puVar1 & 0xffffdfff | param_3 << 0xd;
      *puVar1 = *puVar1 & 0xfffe3fff | param_4 << 0xe;
      break;
    case 0xc:
      *puVar1 = *puVar1 & 0xfffdffff | param_3 << 0x11;
      *puVar1 = *puVar1 & 0xffe3ffff | param_4 << 0x12;
      break;
    case 0xd:
      *puVar1 = *puVar1 & 0xffdfffff | param_3 << 0x15;
      *puVar1 = *puVar1 & 0xfe3fffff | param_4 << 0x16;
      *puVar1 = *puVar1 & 0xc1ffffff | param_5 << 0x19;
      break;
    case 0xe:
      *puVar2 = *puVar2 & 0xfffffffe | param_3;
      *puVar2 = *puVar2 & 0xfffffff1 | param_4 << 1;
      *puVar2 = *puVar2 & 0xfffffe0f | (param_5 & 0xff) << 4;
      break;
    case 0xf:
      *puVar2 = *puVar2 & 0xfffffdff | param_3 << 9;
      *puVar2 = *puVar2 & 0xffffe3ff | param_4 << 10;
      *puVar2 = *puVar2 & 0xfffc1fff | (param_5 & 0xff) << 0xd;
      break;
    case 0x10:
      *puVar2 = *puVar2 & 0xfffbffff | param_3 << 0x12;
      *puVar2 = *puVar2 & 0xffc7ffff | param_4 << 0x13;
      *puVar2 = *puVar2 & 0xf83fffff | (param_5 & 0xff) << 0x16;
      break;
    case 0x11:
      *puVar2 = *puVar2 & 0xf7ffffff | param_3 << 0x1b;
      *puVar2 = *puVar2 & 0x8fffffff | param_4 << 0x1c;
      *puVar3 = *puVar3 & 0xffffffe0 | param_5 & 0xff;
      break;
    case 0x12:
      *puVar3 = *puVar3 & 0xffffffdf | param_3 << 5;
      *puVar3 = *puVar3 & 0xfffffe3f | param_4 << 6;
      *puVar3 = *puVar3 & 0xffffc1ff | (param_5 & 0xff) << 9;
      break;
    case 0x13:
      *puVar3 = *puVar3 & 0xffffbfff | param_3 << 0xe;
      *puVar3 = *puVar3 & 0xfffc7fff | param_4 << 0xf;
      *puVar3 = *puVar3 & 0xff83ffff | (param_5 & 0xff) << 0x12;
      break;
    case 0x14:
      *puVar3 = *puVar3 & 0xff7fffff | param_3 << 0x17;
      *puVar3 = *puVar3 & 0xf8ffffff | param_4 << 0x18;
      *puVar3 = param_5 << 0x1b | *puVar3 & 0x7ffffff;
    }
  }
  *(uint *)(PTR_DAT_803ad640 + 0x4f0) = *(uint *)(PTR_DAT_803ad640 + 0x4f0) | 0x10;
  PTR_DAT_803ad640[0x4ee] = PTR_DAT_803ad640[0x4ee] | (byte)(1 << (param_1 & 0xff));
  return;
}

```

### 0x80102ef8 (15 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x80102ef8; retail_virtual; canonical original-file offset 0xffef8. This is not original source or a verified behavior reconstruction. */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80102ef8(uint param_1)

{
  _DAT_cc008000 = param_1 & 0xff;
  *(uint *)(PTR_DAT_803ad640 + 0x204) =
       *(uint *)(PTR_DAT_803ad640 + 0x204) & 0xffffff8f | (param_1 & 0xff) << 4;
  *(uint *)(PTR_DAT_803ad640 + 0x4f0) = *(uint *)(PTR_DAT_803ad640 + 0x4f0) | 4;
  return;
}

```

### 0x80105850 (13 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x80105850; retail_virtual; canonical original-file offset 0x102850. This is not original source or a verified behavior reconstruction. */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80105850(undefined4 param_1,int param_2)

{
  _DAT_cc008000 = param_2 << 2 | 0xb0000;
  FUN_801057c4(param_1,&DAT_cc008000);
  return;
}

```

### 0x8010588c (13 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8010588c; retail_virtual; canonical original-file offset 0x10288c. This is not original source or a verified behavior reconstruction. */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8010588c(undefined4 param_1,int param_2)

{
  _DAT_cc008000 = param_2 * 3 + 0x400U | 0x80000;
  FUN_801057f8(param_1,&DAT_cc008000);
  return;
}

```

### 0x80105908 (32 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x80105908; retail_virtual; canonical original-file offset 0x102908. This is not original source or a verified behavior reconstruction. */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80105908(undefined4 param_1,uint param_2,int param_3)

{
  int iVar1;
  
  if (param_2 < 0x40) {
    _DAT_cc008000 = param_2 << 2;
  }
  else {
    _DAT_cc008000 = (param_2 - 0x40) * 4 + 0x500;
  }
  if (param_3 == 1) {
    iVar1 = 8;
  }
  else {
    iVar1 = 0xc;
  }
  _DAT_cc008000 = _DAT_cc008000 | (iVar1 + -1) * 0x10000;
  if (param_3 == 0) {
    FUN_801057c4(param_1,&DAT_cc008000);
  }
  else {
    FUN_8010582c(param_1,&DAT_cc008000);
  }
  return;
}

```

### 0x8011c628 (45 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011c628; retail_virtual; canonical original-file offset 0x119628. This is not original source or a verified behavior reconstruction. */


void FUN_8011c628(uint param_1,undefined2 *param_2)

{
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  undefined4 local_c;
  undefined4 local_8 [2];
  
  if (((param_1 & 0xff) - 0x10 & 1) != 0) {
    local_2c = CONCAT22(CONCAT11((char)param_2[1],(char)((ushort)*param_2 >> 8)),
                        CONCAT11((char)*param_2,(char)((ushort)param_2[1] >> 8)));
    local_8[0] = local_2c;
    if ((DAT_803ae0e8 & 0x10) == 0) {
      if ((DAT_803ae0e8 & 0x20) == 0) {
        FUN_80102d90(4,&local_2c);
      }
      else {
        FUN_80113fc0(local_8,&local_1c);
        local_1c = local_1c + DAT_803578b0;
        local_18 = local_18 + DAT_803578b4;
        local_14 = local_14 + DAT_803578b8;
        local_10 = local_10 + DAT_803578bc;
        FUN_80113f98(&local_1c,&local_20);
        local_28 = local_20;
        FUN_80102d90(4,&local_28);
      }
    }
    else {
      FUN_80113f98(&DAT_803578b0,&local_c);
      local_24 = local_c;
      FUN_80102d90(4,&local_24);
    }
  }
  return;
}

```

### 0x8011c754 (11 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011c754; retail_virtual; canonical original-file offset 0x119754. This is not original source or a verified behavior reconstruction. */


void FUN_8011c754(uint param_1)

{
  DAT_803ae0dc = param_1 & 0x3f00;
  DAT_803ae144 = DAT_803ae144 | 8;
  return;
}

```

### 0x8011c76c (37 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011c76c; retail_virtual; canonical original-file offset 0x11976c. This is not original source or a verified behavior reconstruction. */


void FUN_8011c76c(uint param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  iVar1 = *(int *)(*(int *)(**(int **)(DAT_803ae098 + 0x20) + (param_2 & 0x1fff) * 0xc + 8) + 0xc);
  DAT_803ae14c = (undefined4 *)(iVar1 + 4);
  uVar3 = 1;
  uVar2 = 1;
  if ((param_1 & 0x2000) == 0) {
    if ((param_1 & 0x8000) != 0) {
      uVar2 = 2;
    }
  }
  else {
    uVar2 = 0;
  }
  if ((param_1 & 0x1000) == 0) {
    if ((param_1 & 0x4000) != 0) {
      uVar3 = 2;
    }
  }
  else {
    uVar3 = 0;
  }
  FUN_8010334c(&DAT_80357fb0,*(undefined4 *)(iVar1 + 0x20),*(uint *)(iVar1 + 0x10) & 0xffff,
               *(uint *)(iVar1 + 0x14) & 0xffff,*DAT_803ae14c,uVar2,uVar3,
               (*(uint *)(iVar1 + 0x1c) & 0x80000000) != 0);
  FUN_8010394c(&DAT_80357fb0,0);
  return;
}

```

### 0x8011c960 (13 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011c960; retail_virtual; canonical original-file offset 0x119960. This is not original source or a verified behavior reconstruction. */


void FUN_8011c960(void)

{
  FUN_80104d14(1);
  FUN_801014a8(0);
  FUN_801044a8(0,4);
  FUN_80104b74(0,0xff,0xff,4);
  return;
}

```

### 0x8011c9ac (13 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011c9ac; retail_virtual; canonical original-file offset 0x1199ac. This is not original source or a verified behavior reconstruction. */


void FUN_8011c9ac(void)

{
  FUN_80104d14(1);
  FUN_801014a8(1);
  FUN_801044a8(0,0);
  FUN_80104b74(0,0,0,4);
  return;
}

```

### 0x8011cc08 (34 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011cc08; retail_virtual; canonical original-file offset 0x119c08. This is not original source or a verified behavior reconstruction. */


void FUN_8011cc08(uint param_1)

{
  char cVar1;
  
  if (DAT_803ae150 == '\0') {
    cVar1 = (param_1 & 0x88) != 0;
  }
  else {
    cVar1 = '\x03';
  }
  FUN_80104ff8(cVar1,(DAT_803ae0dc & 0x3800) >> 0xb,(DAT_803ae0dc & 0x700) >> 8,0);
  if (cVar1 == '\x03') {
    FUN_80122ab4();
  }
  else if (cVar1 == '\x01') {
    if (((((param_1 & 0x80) == 0) && ((DAT_803ae0dc & 0x3800) != 0x800)) &&
        ((DAT_803ae0dc & 0x700) != 0x100)) &&
       ((DAT_803ae14c != (int *)0x0 && (*DAT_803ae14c == 0xe)))) {
      FUN_80122a44();
    }
    else {
      FUN_80122ab4();
    }
  }
  else {
    FUN_801229ec();
  }
  return;
}

```

### 0x8011d2f4 (30 lines; complete)

```c
/* Generated, unreviewed Ghidra pseudocode. Entry 0x8011d2f4; retail_virtual; canonical original-file offset 0x11a2f4. This is not original source or a verified behavior reconstruction. */


void FUN_8011d2f4(void)

{
  undefined1 auStack_98 [48];
  undefined1 auStack_68 [48];
  undefined1 auStack_38 [52];
  
  FUN_80100d44(0,9,1,4,0);
  FUN_80100d44(0,10,0,4,0);
  FUN_80100d44(0,0xb,1,5,0);
  FUN_80102ef8(1);
  DAT_803ae140 = 0;
  DAT_803ae144 = 0xffffffff;
  DAT_803ae148 = 0;
  FUN_80105850(&DAT_80357880,0);
  FUN_8010588c(&DAT_80357880,0);
  if ((DAT_803ae0e8 & 0x100000) == 0) {
    FUN_800ed7cc((double)DAT_803b0fb8,(double)DAT_803b0fb8,(double)DAT_803b0fbc,auStack_38);
    FUN_800ed798((double)DAT_803b0fc0,(double)DAT_803b0fc0,(double)DAT_803b0fc4,auStack_68);
    FUN_800ed368(auStack_38,&DAT_80357880,auStack_98);
    FUN_800ed368(auStack_68,auStack_98,auStack_98);
    FUN_80105908(auStack_98,0x2a,0);
    DAT_803ae0e8 = DAT_803ae0e8 | 0x100000;
  }
  return;
}

```
