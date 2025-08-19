#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  vmxeditor.py 1.0.0
#
#  Written 2020-2023 by Robert Federle <r.federle3@gmx.de>
#
# Code is based on https://wiki.wxpython.org/Create%20a%20simple%20text%20editor%20%28Phoenix%29
#
# requirements: vmwarevmx
# requirements: wxPython
#
# Installation:
# https://wiki.wxpython.org/How%20to%20install%20wxPython
# macOS: pip install -U wxPython

__version__ = '1.0.0'

import os.path
import re
import sys
from vmwarevmx import VMwareVMX
import wx
import wx.stc as stc   # StyledTextCtrl

# class MyFrame
# class MyApp

#-------------------------------------------------------------------------------

# This is how you pre-establish a file filter so that the
# dialog only shows the extension(s) you want it to.

wildcard = "VMWare Configuration (*.vmx)|*.vmx|" \
           "Text (*.txt)|*.txt|" \
           "All (*.*)|*.*|"

#----------------------------------------------------------------------

if wx.Platform == '__WXMSW__':
    faces = { 'times': 'Times New Roman',
              'mono' : 'Courier New',
              'helv' : 'Arial',
              'other': 'Comic Sans MS',
              'size' : 10,
              'size2': 8,
            }
elif wx.Platform == '__WXMAC__':
    faces = { 'times': 'Times New Roman',
              'mono' : 'Monaco',
              'helv' : 'Arial',
              'other': 'Comic Sans MS',
              'size' : 12,
              'size2': 10,
            }
else:
    faces = { 'times': 'Times',
              'mono' : 'Courier',
              'helv' : 'Helvetica',
              'other': 'new century schoolbook',
              'size' : 12,
              'size2': 10,
            }

#-------------------------------------------------------------------------------

class MyFrame(wx.Frame):
    def __init__(self, area, filename='Untitled'):
        # MyFrame overrides wx.Frame, so we have to call it using super:
        super(MyFrame, self).__init__(None, pos=(area.x, area.y), size=(800, 600))

        self.dirname = '.'
        self.encoding = ''
        self.filename = filename
        self.finddata = None
        self.finddialog = None
        self.iconsDir = wx.GetApp().GetIconsDir()
        self.lines = 0
        self.password = None
        self.vmx = None

        # Simplified init method.
        self.setProperties()
        self.createMenuBar()
        self.createStyledTextControl()
        self.createStatusBar()
        self.bindEvents()
        self.lineNumbers(self.lines)

        self.TextObj.EmptyUndoBuffer()

        # Default status is not encrypted
        self.encrypted = False
        # Default is not modified
        self.modified = False
        # Default is insert mode (not replacing characters)
        self.replace = False

    #---------------------------------------------------------------------------

    @property
    def encrypted(self):
        try:
            return self.__encrypted
        except AttributeError:
            return False


    @encrypted.setter
    def encrypted(self, value):
        self.__encrypted = value
        if value:
            self.setEncryptionStatus('ENC')
        else:
            self.setEncryptionStatus('')

    #---------------------------------------------------------------------------

    @property
    def modified(self):
        try:
            return self.__modified
        except AttributeError:
            return False


    @modified.setter
    def modified(self, value):
        try:
            oldvalue = self.__modified
        except AttributeError:
            oldvalue = False
        if oldvalue != value:
            self.__modified = value
            self.SetTitle()

    #---------------------------------------------------------------------------

    def caretCurrentPosition(self):
        pos = self.TextObj.GetCurrentPos()
        success, column, line = self.TextObj.PositionToXY(pos)
        displayline = self.TextObj.GetFirstVisibleLine()


    def caretRestorePosition(self):
        line = min(self.caretline, self.TextObj.GetNumberOfLines() - 1)
        displayline = min(self.caretdisplayline, self.TextObj.GetNumberOfLines() - 1)
        column = self.caretcolumn
        pos = self.TextObj.XYToPosition(column, line)
        # XYToPosition() returns an error at end of buffer, so use GetLineEndPosition() in that case instead
        if pos == -1:
            pos = self.TextObj.GetLineEndPosition(line)

        self.TextObj.GotoPos(pos)
        self.TextObj.PageDown()
        self.TextObj.PageUp()
        self.TextObj.GotoPos(pos)
        self.TextObj.SetFirstVisibleLine(displayline)
        # self.TextObj.ScrollToLine(line)


    def caretSavePosition(self):
        pos = self.TextObj.GetCurrentPos()
        # Do not use PositionToXY() here as it fails if the caret is positioned after the last character of a line
        self.caretcolumn = self.TextObj.GetColumn(pos)
        self.caretline = self.TextObj.GetCurrentLine()
        self.caretdisplayline = self.TextObj.GetFirstVisibleLine()


    def lineNumbers(self, lines):
        width = self.TextObj.TextWidth(stc.STC_STYLE_LINENUMBER, str(lines) + " ")
        self.TextObj.SetMarginWidth(0, width)


    def setEncryptionStatus(self, status):
        self.statusbar.SetStatusText(status, 2)


    def setFileStatus(self, status):
        self.statusbar.SetStatusText(status, 0)


    def setInsertStatus(self, status):
        self.statusbar.SetStatusText(status, 1)


    def setProperties(self):
        frameIcon = wx.Icon(os.path.join(self.iconsDir, "icon_wxWidgets.ico"),
                            type=wx.BITMAP_TYPE_ICO)
        self.SetIcon(frameIcon)


    def SetTitle(self):
        # MyFrame.SetTitle overrides wx.Frame.SetTitle,
        # so we have to call it using super:
        modifiedtext = ' - modified' if self.modified else ''
        super(MyFrame, self).SetTitle(self.filename + modifiedtext)

    #---------------------------------------------------------------------------

    def createMenuBar(self):
        """
        Create menu and menu bar.
        """ 
        menuBar = wx.MenuBar()

        #------------

        menu_File = wx.Menu()
        menu_Edit = wx.Menu()
        menu_Window = wx.Menu()
        menu_Help = wx.Menu()

        #------------

        self.menu_File_New = menu_File.Append(wx.ID_NEW,
                                              "&New Document" + "\t" + "Ctrl+N",
                                              "Create a new document")
        self.menu_File_Open = menu_File.Append(wx.ID_OPEN,
                                               "&Open..." + "\t" + "Ctrl+O",
                                               "Open a file")

        #------------

        menu_File.AppendSeparator()

        #------------

        self.menu_File_Close = menu_File.Append(wx.ID_CLOSE,
                                                "&Close Window" + "\t" + "Ctrl+W",
                                                "Close Window")
        self.menu_File_Save = menu_File.Append(wx.ID_SAVE,
                                               "&Save" + "\t" + "Ctrl+S",
                                               "Save the current file")
        self.menu_File_SaveAs = menu_File.Append(wx.ID_SAVEAS,
                                                 "Save &As..." + "\t" + "Ctrl+Shift+S",
                                                 "Save the file under a different name")

        #------------

        menu_File.AppendSeparator()

        #------------

        self.menu_File_Decrypt = menu_File.Append(wx.ID_ANY,
                                                  "&Decrypt File" + "\t" + "Ctrl+D",
                                                  "Decrypt file")
        self.menu_File_Encrypt = menu_File.Append(wx.ID_ANY,
                                                  "&Encrypt File" + "\t" + "Ctrl+E",
                                                  "Encrypt file")
        self.menu_File_ChangePW = menu_File.Append(wx.ID_ANY,
                                                  "&Password..." + "\t" + "Ctrl+Shift+P",
                                                  "Enter the password")

        #------------

        menu_File.AppendSeparator()

        #------------

        self.menu_Program_Close = menu_File.Append(wx.ID_EXIT,
                                                   "&Exit" + "\t" + "Ctrl+X",
                                                   "Exit the program")

        #------------

        self.menu_Edit_Undo = menu_Edit.Append(wx.ID_UNDO,
                                               "&Undo" + "\t" + "Ctrl+Z",
                                               "Undo")
        self.menu_Edit_Redo = menu_Edit.Append(wx.ID_REDO,
                                               "&Redo" + "\t" + "Ctrl+Shift+Z",
                                               "Redo")

        #------------

        menu_Edit.AppendSeparator()

        #------------

        self.menu_Edit_Cut = menu_Edit.Append(wx.ID_CUT,
                                              "&Cut" + "\t" + "Ctrl+X",
                                              "Cut")
        self.menu_Edit_Copy = menu_Edit.Append(wx.ID_COPY,
                                               "&Copy" + "\t" + "Ctrl+C",
                                               "Copy")
        self.menu_Edit_Paste = menu_Edit.Append(wx.ID_PASTE,
                                                "&Paste" + "\t" + "Ctrl+V",
                                                "Paste")

        #------------

        menu_Edit.AppendSeparator()

        #------------

        self.menu_Edit_SelectAll = menu_Edit.Append(wx.ID_SELECTALL,
                                                    "Select &All" + "\t" + "Ctrl+A",
                                                    "Select All")

        #------------

        menu_Edit.AppendSeparator()

        #------------

        self.menu_Edit_Find = menu_Edit.Append(wx.ID_ANY,
                                               "&Find..." + "\t" + "Ctrl+F",
                                               "Find")

        self.menu_Edit_FindNext = menu_Edit.Append(wx.ID_ANY,
                                                   "Find Next" + "\t" + "Ctrl+G",
                                                   "Find Next")

        self.menu_Edit_FindPrev = menu_Edit.Append(wx.ID_ANY,
                                                   "Find Previous" + "\t" + "Ctrl+Shift+G",
                                                   "Find Previous")

        #------------

        self.menu_Help_About = menu_Help.Append(wx.ID_ABOUT,
                                                "&About VMXEditor",
                                                "Information about this program")

        #------------

        menuBar.Append(menu_File,   "&File")
        menuBar.Append(menu_Edit,   "&Edit")
        menuBar.Append(menu_Window, "&Window")
        menuBar.Append(menu_Help,   "&Help")

        #------------

        self.SetMenuBar(menuBar)

    #---------------------------------------------------------------------------

    def createStyledTextControl(self):
        self.TextObj = stc.StyledTextCtrl(self)
        self.TextObj.SetWindowStyle(self.TextObj.GetWindowStyle() | wx.DOUBLE_BORDER)
        self.TextObj.SetWrapMode(stc.STC_WRAP_WORD)

        layout = wx.BoxSizer(wx.HORIZONTAL)
        layout.Add(self.TextObj, proportion=1, border=0, flag=wx.ALL|wx.EXPAND)
        self.SetSizer(layout)

        self.TextObj.SetSelBackground(True, wx.SystemSettings.GetColour(wx.SYS_COLOUR_HIGHLIGHT))
        self.TextObj.SetLexer(stc.STC_LEX_CAML)
        self.TextObj.StyleSetSpec(stc.STC_STYLE_DEFAULT,   "face:%(mono)s,size:%(size)d" % faces)
        self.TextObj.StyleSetSpec(stc.STC_CAML_IDENTIFIER, "face:%(mono)s,size:%(size)d,bold" % faces)

    #---------------------------------------------------------------------------

    def createStatusBar(self):
        # MyFrame.CreateStatusBar overrides wx.Frame.CreateStatusBar,
        # so we have to call it using super:
        self.statusbar = super(MyFrame, self).CreateStatusBar()
        self.statusbar.SetFieldsCount(3)
        self.statusbar.SetStatusWidths([-10, -1, -1])

    #---------------------------------------------------------------------------

    def bindEvents(self):
        self.Bind(wx.EVT_MENU, self.OnAbout,       self.menu_Help_About)
        self.Bind(wx.EVT_MENU, self.OnCloseApp,    self.menu_Program_Close)
        self.Bind(wx.EVT_MENU, self.OnNew,         self.menu_File_New)
        self.Bind(wx.EVT_MENU, self.OnOpen,        self.menu_File_Open)
        self.Bind(wx.EVT_MENU, self.OnCloseWindow, self.menu_File_Close)
        self.Bind(wx.EVT_MENU, self.OnSave,        self.menu_File_Save)
        self.Bind(wx.EVT_MENU, self.OnSaveAs,      self.menu_File_SaveAs)
        self.Bind(wx.EVT_MENU, self.OnDecrypt,     self.menu_File_Decrypt)
        self.Bind(wx.EVT_MENU, self.OnEncrypt,     self.menu_File_Encrypt)
        self.Bind(wx.EVT_MENU, self.OnChangePW,    self.menu_File_ChangePW)
        self.Bind(wx.EVT_MENU, self.OnUndo,        self.menu_Edit_Undo)
        self.Bind(wx.EVT_MENU, self.OnRedo,        self.menu_Edit_Redo)
        self.Bind(wx.EVT_MENU, self.OnCut,         self.menu_Edit_Cut)
        self.Bind(wx.EVT_MENU, self.OnCopy,        self.menu_Edit_Copy)
        self.Bind(wx.EVT_MENU, self.OnPaste,       self.menu_Edit_Paste)
        self.Bind(wx.EVT_MENU, self.OnSelectAll,   self.menu_Edit_SelectAll)
        self.Bind(wx.EVT_MENU, self.OnFind,        self.menu_Edit_Find)
        self.Bind(wx.EVT_MENU, self.OnFindNext,    self.menu_Edit_FindNext)
        self.Bind(wx.EVT_MENU, self.OnFindPrev,    self.menu_Edit_FindPrev)

        self.Bind(wx.EVT_CLOSE, self.OnCloseWindow)
        self.Bind(wx.EVT_FIND, self.OnTextFind)
        self.Bind(wx.EVT_FIND_NEXT, self.OnTextFind)
        # self.Bind(wx.EVT_FIND_REPLACE, self.OnTextReplace)
        # self.Bind(wx.EVT_FIND_REPLACE_ALL, self.OnTextReplaceAll)
        self.Bind(wx.EVT_FIND_CLOSE, self.OnFindClose)

        self.TextObj.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)
        self.TextObj.Bind(stc.EVT_STC_CHANGE, self.OnTextModified)

    #---------------------------------------------------------------------------

    def AskUserForFilename(self, **dialogOptions):
        """
        Open a dialog and ask for a filename and path. If the user
        aborts, return False, headerwise True.
        """
        with wx.FileDialog(self, **dialogOptions) as dialog:
            if dialog.ShowModal() == wx.ID_CANCEL:
                return False

            self.filename = dialog.GetFilename()
            self.dirname = dialog.GetDirectory()
            return True


    def AskUserForInput(self, message, caption, value, password=False):
        """
        Open a dialog with a message and ask for some text. If the user
        aborts, return None, headerwise the entered text.
        """
        if password:
            style = wx.OK | wx.CANCEL | wx.TE_PASSWORD
        else:
            style = wx.OK | wx.CANCEL | wx.TE_MULTILINE

        with wx.TextEntryDialog(self, message, caption, value, style) as dialog:
            if dialog.ShowModal() == wx.ID_OK:
                return dialog.GetValue()
            else:
                return None


    def DefaultFileDialogOptions(self):
        """
        Return a dictionary with file dialog options that can be
        used in both the save file dialog as well as in the open
        file dialog.
        """
        return dict(message="Choose a file:",
                    defaultDir=self.dirname,
                    wildcard=wildcard)


    def ErrorDialog(self, message):
        wx.MessageBox(message, "Error:", wx.OK | wx.ICON_ERROR)


    def IsEncrypted(self):
        lines = self.TextObj.GetValue().split('\n')
        for line in lines:
            if re.match(r'^encryption.keySafe *= *"vmware:key/list/\(pair/\(phrase/(.+)pass2key(.+)\)\)"$', line):
                return True
        return False


    def NewFile(self):
        return wx.GetApp().NewFrame()


    def OpenFile(self, dirname, filename):
        if dirname == '':
            dirname = '.'
        try:
            file = open(os.path.join(dirname, filename), 'r', encoding='utf-8')
            content = file.read()
            if len(content) > 0 and content[-1:] == '\n':
                # remove last newline character
                content = content[:-1]
            self.TextObj.ChangeValue(content)
            self.TextObj.EmptyUndoBuffer()
            self.dirname = dirname
            self.filename = filename
            self.modified = False
            self.encrypted = self.IsEncrypted()
            return True
        except (OSError, IOError):
            self.ErrorDialog("Cannot read from file " + filename)
            return False


    def SaveFile(self):
        if self.modified:
            try:
                encoding = 'utf-8' if self.encoding == '' else self.encoding
                with open(os.path.join(self.dirname, self.filename), 'w', encoding=encoding) as file:
                    file.write(self.TextObj.GetValue() + '\n')
                    self.modified = False
            except (OSError, IOError):
                self.ErrorDialog("Cannot write file " + self.filename)

    #---------------------------------------------------------------------------

    def OnAbout(self, event):
        """
        About dialog.
        """
        wx.MessageBox("A simple text editor for VMware VMX configuration files.\n\n"
                      "Original code (C) wxPython wiki:\n\n"
                      "https://wiki.wxpython.org/Create a simple text editor (Phoenix)\n\n"
                      "Additional VMwareVMX code (C) 2020-2023 Robert Federle",
                      "About VMXEditor",
                      wx.OK)


    def OnCloseApp(self, event=None):
        """
        Quit and destroy application.
        """
        if 'wxMac' not in wx.PlatformInfo:
            wx.TheClipboard.Flush()
        wx.GetApp().DestroyAllFrames()

    def OnNew(self, event):
        """
        Create a new document.
        """
        self.NewFile().Show(True)


    def OnOpen(self, event):
        """
        Open file.
        """
        new = self.NewFile()
        if new.AskUserForFilename(style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
                                   **new.DefaultFileDialogOptions()):
            if new.OpenFile(new.dirname, new.filename):
                new.Show(True)
                return
        wx.GetApp().DestroyFrame(new)


    def OnCloseWindow(self, event=None):
        """
        Close the current window.
        """
        if self.modified:
            answer = wx.MessageBox("Do you want to discard the changes?",
                                   "File has been modified",
                                    wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION)
            if answer == wx.NO:
                return False
        wx.GetApp().DestroyFrame(self)
        return True


    def OnSave(self, event):
        """
        Save file.
        """
        if self.filename == '':
            self.OnSaveAs(event)
        else:
            self.SaveFile()


    def OnSaveAs(self, event):
        """
        Save file as.
        """
        if self.AskUserForFilename(defaultFile=self.filename,
                                   style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
                                   **self.DefaultFileDialogOptions()):
            self.SaveFile()


    def OnDecrypt(self, event):
        """
        Decrypt file.
        """
        header = ''
        keysafe, data = None, None

        lines = self.TextObj.GetValue().split('\n')
        for line in lines:
            if line == '':
                continue
            match = re.match('^.encoding *= *"(.+)"$', line)
            if match:
                self.encoding = match.group(1).lower()

            if re.match(r'^encryption.keySafe *= *"vmware:key/list/\(pair/\(phrase/(.+)pass2key(.+)\)\)"$', line):
                keysafe = line
            elif re.match('^encryption.data *= *"(.+)"$', line):
                data = line
            else:
                header = header + line + '\n'

        if keysafe is None or data is None:
           self.ErrorDialog("File is not an encrypted VMware VMX configuration or corrupted")
        else:
            password = self.password
            if password is None:
                password = self.AskUserForInput("Enter the password to decrypt the file:",
                                                "VMX Configuration Password",
                                                "",
                                                password=True)

            if password:
                try:
                    self.vmx = VMwareVMX.new()
                    encoding = 'utf-8' if self.encoding == '' else self.encoding
                    config = self.vmx.decrypt(password, keysafe, data, encoding)
                    if config is None:
                        self.ErrorDialog("Password is invalid")
                    else:
                        self.password = password
                        # skip last newline character
                        config = header + config[:-1]
                        self.caretSavePosition()
                        self.TextObj.ChangeValue(config)
                        self.caretRestorePosition()
                        # Change status to not encrypted
                        self.encrypted = False
                except ValueError as err:
                    self.ErrorDialog(str(err))


    def OnEncrypt(self, event):
        """
        Encrypt file.
        """
        if self.encrypted:
            self.ErrorDialog("File is already an encrypted VMware VMX configuration")
            return

        if self.password is None:
            self.OnChangePW(None)
            if self.password is None:
                return

        if self.vmx is None:
            self.vmx = VMwareVMX.new()

        if self.encoding == '':
            self.encoding = 'utf-8'

        header = ''
        config = ''
        lines = self.TextObj.GetValue().split('\n')
        for line in lines:
            if line == '':
                continue
            match = re.match('^.encoding *= *"(.+)"$', line)
            if match:
                self.encoding = match.group(1).lower()
                header = header + line + '\n'
            elif re.match('^display[Nn]ame *= *"(.+)"$', line):
                header = header + line + '\n'
            elif  re.match('^guestOS.detailed.data *= *"(.+)"$', line):
                header = header + line + '\n'
            elif re.match('^guestInfo.detailed.data *= *"(.+)"$', line):
                header = header + line + '\n'
            else:
                config = config + line + '\n'

        hash_rounds = self.vmx.hash_rounds

        try:
            keysafe, data = self.vmx.encrypt(self.password, config, hash_rounds)
        except ValueError as err:
            self.ErrorDialog(str(err))

        config = header + keysafe + '\n' + data
        self.caretSavePosition()
        self.TextObj.ChangeValue(config)
        self.caretRestorePosition()
        # Change status to encrypted
        self.encrypted = True


    def OnChangePW(self, event):
        """
        Change password.
        """
        while True:
            # Get 1st password
            password1 = self.AskUserForInput("Enter the password for the file:",
                                             "VMX Configuration Password",
                                             "",
                                             password=True)
            # Dialog aborted?
            if password1 is None:
                return
            # No password?
            elif password1 == '':
                self.ErrorDialog("Empty password is not allowed")
            else:
                # Only ask once for a password if file is already encrypted
                if self.encrypted:
                    self.password = password1
                    return
                else:
                    # Get 2nd password
                    password2 = self.AskUserForInput("Enter the password again to verify:",
                                                        "VMX Configuration Password",
                                                        "",
                                                        password=True)
                    # Dialog aborted?
                    if password2 is None:
                        return
                    # No matching passwords?
                    elif password1 != password2:
                        self.ErrorDialog("Passwords don't match")
                    # Both passwords match => this is now our new password
                    else:
                        self.password = password1
                        return


    def OnUndo(self, event):
        if self.TextObj.CanUndo():
            self.caretSavePosition()
            self.TextObj.Undo()
            self.caretRestorePosition()
            self.encrypted = self.IsEncrypted()
            if self.TextObj.CanUndo() == False:
                self.modified = False


    def OnRedo(self, event):
        if self.TextObj.CanRedo():
            self.caretSavePosition()
            self.TextObj.Redo()
            self.caretRestorePosition()
            self.encrypted = self.IsEncrypted()
            self.modified = True


    def OnCut(self, event):
        self.TextObj.Cut()


    def OnCopy(self, event):
        self.TextObj.Copy()


    def OnPaste(self, event):
        self.TextObj.Paste()


    def OnSelectAll(self, event):
        self.TextObj.SelectAll()


    def OnFind(self, event):
        if not self.finddata:
            self.finddata = wx.FindReplaceData()
        else:
            # deactivate backward search
            self.finddata.SetFlags(self.finddata.GetFlags() & ~wx.FR_DOWN)
        if not self.finddialog:
            self.finddialog = wx.FindReplaceDialog(self.TextObj, self.finddata, 'Find', 0) # wx.FR_REPLACEDIALOG
            self.finddialog.Show()


    def OnFindClose(self, event):
        # if dialog is still open, close it
        if self.finddialog:
            self.finddialog.Destroy()
            self.finddialog = None


    def OnFindNext(self, event):
        if self.finddata:
            # deactivate backward search
            self.finddata.SetFlags(self.finddata.GetFlags() & ~wx.FR_DOWN)
            self.OnTextFind(event)


    def OnFindPrev(self, event):
        if self.finddata:
            # activate backward search
            self.finddata.SetFlags(self.finddata.GetFlags() | wx.FR_DOWN)
            self.OnTextFind(event)


    def OnDelete(self, event):
        frm, to = self.TextObj.GetSelection()
        self.TextObj.Remove(frm, to)


    def OnKeyDown(self, event):
        keycode = event.GetKeyCode()
        if keycode == wx.WXK_INSERT:
            if not self.replace:
                self.SetInsertStatus('INS')
                self.replace = True
            else:
                self.SetInsertStatus('')
                self.replace = False
        event.Skip()


    def OnTextFind(self, event):
        start, end = self.TextObj.GetSelection()
        # get the search direction
        backwards = self.finddata.GetFlags() & wx.FR_DOWN
        # get the other search flags without the search direction
        flags = self.finddata.GetFlags() & ~wx.FR_DOWN
        findstring = self.finddata.GetFindString()

        if backwards:
            # if start is not equal end position, then we have a selection
            if start != end:
                # place the caret one character before the current end position of the selection
                self.TextObj.GotoPos(end - 1)
            self.TextObj.SearchAnchor()
            findpos = self.TextObj.SearchPrev(flags, findstring)
        else:
            # place the caret one character after the current start position
            self.TextObj.GotoPos(start + 1)
            self.TextObj.SearchAnchor()
            findpos = self.TextObj.SearchNext(flags, findstring)

        if findpos >= 0:
            findlength = len(findstring)
            # place the caret after the text found
            self.TextObj.GotoPos(findpos + findlength)
            self.TextObj.ScrollRange(findpos, findpos + findlength)
            # select the text
            self.TextObj.SetSelection(findpos, findpos + findlength)
        else:
            # play system sound
            print('\a', end='', flush=True)
            # restore a previous selection
            self.TextObj.SetSelection(start, end)
 

    def OnTextModified(self, event):
        lines = self.TextObj.GetLineCount()
        if lines != self.lines:
            self.lines = lines
            text = str(lines) + " line" + (lines != 1) * 's'
            self.setFileStatus(text)
            self.lineNumbers(lines)
        self.modified = True
        event.Skip()

#-------------------------------------------------------------------------------

class MyApp(wx.App):
    def OnInit(self):
        self.installDir = os.path.split(os.path.abspath(sys.argv[0]))[0]
        self.framelist = [ ]

        if len(sys.argv) > 1:
            for filepath in sys.argv[1:]:
                self.MacOpenFile(filepath)
        else:
            self.NewFrame().Show(True)
        return True


    def NewFrame(self):
        area = wx.Display().GetClientArea()
        frame = MyFrame(area=area)
        self.framelist.append(frame)
        self.SetTopWindow(frame)
        return frame


    def DestroyFrame(self, frame):
        self.framelist.remove(frame)
        frame.Destroy()


    def DestroyAllFrames(self):
        while self.framelist:
            if self.framelist[0].OnCloseWindow() == False:
                break


    def MacOpenFile(self, filepath):
        new = self.NewFrame()
        if new.OpenFile(os.path.dirname(filepath), os.path.basename(filepath)):
            new.Show(True)
        else:
            self.DestroyFrame(new)


    def MacReopenApp(self):
        self.GetTopWindow().Raise()


    def MacNewFile(self):
        pass


    def MacPrintFile(self, filepath):
        pass

    #---------------------------------------------------------------------------


    def GetIconsDir(self):
        """
        Returns the icons directory for my application.
        """
        return os.path.join(self.installDir, "icons")

#-------------------------------------------------------------------------------

def main():
    app = MyApp(False)
    app.MainLoop()

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
