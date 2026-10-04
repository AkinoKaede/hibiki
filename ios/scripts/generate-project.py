#!/usr/bin/env python3
"""Reproducible Xcode project without a project-generator dependency."""
from pathlib import Path
import hashlib, json, plistlib
ROOT=Path(__file__).resolve().parents[1]
project=ROOT/'HIbiki.xcodeproj'; project.mkdir(exist_ok=True)
objects={}
def uid(name):return hashlib.sha256(name.encode()).hexdigest()[:24].upper()
def add(key_name,isa,**fields):
    key=uid(key_name);objects[key]={'isa':isa,**fields};return key

def ref(path,kind):return add('file:'+path,'PBXFileReference',lastKnownFileType=kind,path=path,sourceTree='<group>')
def build(refid):return add('build:'+refid,'PBXBuildFile',fileRef=refid)
appfiles=[ref('HIbiki/'+p.name,'sourcecode.swift') for p in sorted((ROOT/'HIbiki').glob('*.swift'))]
binding=ref('Generated/hibiki_mobile.swift','sourcecode.swift')
testfiles=[ref('HIbikiTests/'+p.name,'sourcecode.swift') for p in sorted((ROOT/'HIbikiTests').glob('*.swift'))]
uifiles=[ref('HIbikiUITests/'+p.name,'sourcecode.swift') for p in sorted((ROOT/'HIbikiUITests').glob('*.swift'))]
resources=[ref('HIbiki/Localizable.xcstrings','text.json.xcstrings'),ref('HIbiki/Assets.xcassets','folder.assetcatalog')]
framework=ref('Frameworks/HIbikiCore.xcframework','wrapper.xcframework')
signing=ref('Signing.xcconfig','text.xcconfig')
devicekit_package=add('package:DeviceKit','XCRemoteSwiftPackageReference',repositoryURL='https://github.com/devicekit/DeviceKit.git',requirement={'kind':'upToNextMajorVersion','minimumVersion':'5.9.0'})
devicekit_product=add('product:DeviceKit','XCSwiftPackageProductDependency',package=devicekit_package,productName='DeviceKit')
devicekit_build=add('build:DeviceKit','PBXBuildFile',productRef=devicekit_product)
products=[];targets=[]
settings={
    'SDKROOT':'iphoneos','IPHONEOS_DEPLOYMENT_TARGET':'18.0','SWIFT_VERSION':'5.0','CLANG_ENABLE_MODULES':'YES','ENABLE_USER_SCRIPT_SANDBOXING':'NO',
    'TARGETED_DEVICE_FAMILY':'1,2','CODE_SIGN_STYLE':'Automatic','SWIFT_EMIT_LOC_STRINGS':'YES','SWIFT_STRICT_CONCURRENCY':'complete',
    'ENABLE_APP_SANDBOX':'YES',
    'MARKETING_VERSION':'0.1.0','CURRENT_PROJECT_VERSION':'1','SUPPORTED_PLATFORMS':'iphoneos iphonesimulator',
}
def configs(name,extra):
    entries=[]
    for mode in ['Debug','Release']:
        values={**settings,**extra}
        if name=='HIbiki' and mode=='Release':
            # CI overrides app-only settings through custom variables. Standard
            # command-line signing overrides also affect Swift package targets.
            values.update({
                'HIBIKI_CODE_SIGN_STYLE':'Automatic',
                'HIBIKI_CODE_SIGN_IDENTITY':'Apple Development',
                'CODE_SIGN_STYLE':'$(HIBIKI_CODE_SIGN_STYLE)',
                'CODE_SIGN_IDENTITY[sdk=iphoneos*]':'$(HIBIKI_CODE_SIGN_IDENTITY)',
                'PROVISIONING_PROFILE_SPECIFIER[sdk=iphoneos*]':'$(HIBIKI_PROVISIONING_PROFILE_SPECIFIER)',
            })
        values.update({'SWIFT_OPTIMIZATION_LEVEL':'-Onone' if mode=='Debug' else '-O','DEBUG_INFORMATION_FORMAT':'dwarf' if mode=='Debug' else 'dwarf-with-dsym'})
        if mode=='Debug':values['SWIFT_ACTIVE_COMPILATION_CONDITIONS']='$(inherited) DEBUG'
        config_fields={'baseConfigurationReference':signing} if name=='project' else {}
        entries.append(add(name+mode,'XCBuildConfiguration',name=mode,buildSettings=values,**config_fields))
    return add(name+'configs','XCConfigurationList',buildConfigurations=entries,defaultConfigurationIsVisible=0,defaultConfigurationName='Release')
for name,files,ptype in [('HIbiki',appfiles+[binding],'application'),('HIbikiTests',testfiles,'bundle.unit-test'),('HIbikiUITests',uifiles,'bundle.ui-testing')]:
    app=name=='HIbiki'
    product=add(name+'product','PBXFileReference',explicitFileType='wrapper.application' if app else 'wrapper.cfbundle',path=name+('.app' if app else '.xctest'),sourceTree='BUILT_PRODUCTS_DIR');products.append(product)
    sources=add(name+'sources','PBXSourcesBuildPhase',buildActionMask=2147483647,files=[build(f) for f in files],runOnlyForDeploymentPostprocessing=0)
    frameworks=add(name+'frameworks','PBXFrameworksBuildPhase',buildActionMask=2147483647,files=[build(framework),devicekit_build] if app else [],runOnlyForDeploymentPostprocessing=0)
    resourcephase=add(name+'resources','PBXResourcesBuildPhase',buildActionMask=2147483647,files=[build(r) for r in resources] if app else [],runOnlyForDeploymentPostprocessing=0)
    extra={'PRODUCT_NAME':'$(TARGET_NAME)','PRODUCT_BUNDLE_IDENTIFIER':'com.akinokaede.hibiki'+('' if app else '.'+name),'GENERATE_INFOPLIST_FILE':'YES'}
    if app:
        extra.update({'INFOPLIST_FILE':'HIbiki/Info.plist','CODE_SIGN_ENTITLEMENTS':'HIbiki/HIbiki.entitlements','ASSETCATALOG_COMPILER_APPICON_NAME':'AppIcon',
        'SWIFT_INCLUDE_PATHS':'$(SRCROOT)/Generated','HEADER_SEARCH_PATHS':'$(SRCROOT)/Generated','OTHER_SWIFT_FLAGS':['$(inherited)','-Xcc','-fmodule-map-file=$(SRCROOT)/Generated/hibiki_mobileFFI.modulemap'],
        'OTHER_LDFLAGS':['$(inherited)','-liconv','-framework','Security','-framework','SystemConfiguration'], 'INFOPLIST_KEY_UILaunchScreen_Generation':'YES'})
    elif name=='HIbikiTests':extra.update({'TEST_HOST':'$(BUILT_PRODUCTS_DIR)/HIbiki.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/HIbiki','BUNDLE_LOADER':'$(TEST_HOST)'})
    else:extra['TEST_TARGET_NAME']='HIbiki'
    phases=[sources,frameworks,resourcephase]
    if app:
        preflight=add(name+'rust-check','PBXShellScriptBuildPhase',buildActionMask=2147483647,files=[],inputPaths=[],outputPaths=[],runOnlyForDeploymentPostprocessing=0,shellPath='/bin/sh',shellScript='set -eu\nif [ ! -f "$SRCROOT/Frameworks/configuration.txt" ] || [ "$(cat "$SRCROOT/Frameworks/configuration.txt")" != "$CONFIGURATION" ]; then\n echo "error: Run ./ios/scripts/build-rust.sh $CONFIGURATION from the repository root before this build."\n exit 1\nfi\n',alwaysOutOfDate=1)
        phases.insert(0,preflight)
    deps=[]
    if not app:
        proxy=add(name+'proxy','PBXContainerItemProxy',containerPortal=uid('project'),proxyType=1,remoteGlobalIDString=uid('target:HIbiki'),remoteInfo='HIbiki')
        deps=[add(name+'dependency','PBXTargetDependency',target=uid('target:HIbiki'),targetProxy=proxy)]
    target=add('target:'+name,'PBXNativeTarget',name=name,productName=name,productReference=product,productType='com.apple.product-type.'+ptype,buildPhases=phases,buildRules=[],dependencies=deps,packageProductDependencies=[devicekit_product] if app else [],buildConfigurationList=configs(name,extra));targets.append(target)
productgroup=add('products','PBXGroup',children=products,name='Products',sourceTree='<group>')
main=add('main','PBXGroup',children=appfiles+[binding]+testfiles+uifiles+resources+[framework,signing,ref('HIbiki/Info.plist','text.plist.xml'),ref('HIbiki/HIbiki.entitlements','text.plist.entitlements'),productgroup],sourceTree='<group>')
add('project','PBXProject',attributes={'LastUpgradeCheck':'1800','BuildIndependentTargetsInParallel':'YES','TargetAttributes':{uid('target:HIbikiTests'):{'TestTargetID':uid('target:HIbiki')},uid('target:HIbikiUITests'):{'TestTargetID':uid('target:HIbiki')}}},buildConfigurationList=configs('project',{'ENABLE_TESTABILITY':'YES'}),compatibilityVersion='Xcode 14.0',developmentRegion='en',hasScannedForEncodings=0,knownRegions=['en','zh-Hans','Base'],mainGroup=main,productRefGroup=productgroup,projectDirPath='',projectRoot='',targets=targets,packageReferences=[devicekit_package])
def render(value,level=0):
    if isinstance(value,dict):return '{\n'+''.join('\t'*(level+1)+json.dumps(str(k))+ ' = '+render(v,level+1)+';\n' for k,v in value.items())+'\t'*level+'}'
    if isinstance(value,list):return '('+', '.join(render(v,level) for v in value)+')'
    if isinstance(value,int):return str(value)
    return json.dumps(value,ensure_ascii=False)
(project/'project.pbxproj').write_text('// !$*UTF8*$!\n'+render({'archiveVersion':1,'classes':{},'objectVersion':56,'objects':objects,'rootObject':uid('project')})+'\n')
scheme=project/'xcshareddata/xcschemes';scheme.mkdir(parents=True,exist_ok=True)
def bref(name,product):return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{uid("target:"+name)}" BuildableName="{product}" BlueprintName="{name}" ReferencedContainer="container:HIbiki.xcodeproj"/>'
(scheme/'HIbiki.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1800" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{bref('HIbiki','HIbiki.app')}</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO">{bref('HIbikiTests','HIbikiTests.xctest')}</TestableReference><TestableReference skipped="NO">{bref('HIbikiUITests','HIbikiUITests.xctest')}</TestableReference></Testables></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">{bref('HIbiki','HIbiki.app')}</BuildableProductRunnable></LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">{bref('HIbiki','HIbiki.app')}</BuildableProductRunnable></ProfileAction><AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
print(project)
